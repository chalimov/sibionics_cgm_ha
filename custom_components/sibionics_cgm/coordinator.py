"""Data update coordinator for SIBIONICS CGM.

Manages BLE connection lifecycle, authentication, data retrieval,
and ARM64 emulator calibration. Pushes calibrated glucose readings
to sensor entities via DataUpdateCoordinator.
"""

from __future__ import annotations

import asyncio
import logging
import math
import struct
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any

from bleak import BleakClient
from bleak.exc import BleakError
from bleak_retry_connector import establish_connection
from homeassistant.components import bluetooth
from homeassistant.components.bluetooth import BluetoothCallbackMatcher
from homeassistant.core import CALLBACK_TYPE, Context, HomeAssistant, callback
from homeassistant.util.ulid import ulid_at_time
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import (
    DATA_STALE_TIMEOUT,
    DOMAIN,
    LIVE_UPDATE_INTERVAL,
    NOTIFY_CHAR_UUID,
    RECONNECT_INTERVAL,
    SERVICE_UUID,
    TREND_ARROWS,
    WRITE_CHAR_UUID,
)
from .crypto import (
    decrypt_response,
    make_activation_packet,
    make_auth_packet,
    make_data_request_packet,
    make_time_sync_packet,
    mmol_to_mgdl,
    parse_mac_address,
)

_LOGGER = logging.getLogger(__name__)

# Glucose validation ranges
RAW_GLUCOSE_MIN = 0.5   # mmol/L — below this is sensor noise / corruption
RAW_GLUCOSE_MAX = 25.0  # mmol/L — single-byte max from protocol
CAL_MGDL_MIN = 20       # mg/dL — below this is physiologically implausible
CAL_MGDL_MAX = 500      # mg/dL — above this is sensor corruption
TEMP_MIN = 25.0          # °C — below is implausible for subcutaneous sensor
TEMP_MAX = 45.0          # °C — above is implausible for subcutaneous sensor
MAX_READINGS_IN_MEMORY = 1440  # 24 hours at 1/min


@dataclass
class GlucoseReading:
    """A single calibrated glucose reading."""

    index: int
    timestamp: datetime
    glucose_mmol: float
    glucose_mgdl: int
    raw_mmol: float
    temperature: float
    trend: str = "stable"


@dataclass
class SibionicsCGMData:
    """Current state of the CGM sensor."""

    connected: bool = False
    glucose_mmol: float | None = None
    glucose_mgdl: int | None = None
    raw_mmol: float | None = None
    temperature: float | None = None
    trend: str = "stable"
    battery: int | None = None
    firmware: str | None = None
    serial: str | None = None
    model: str | None = None
    last_reading_time: datetime | None = None
    reading_count: int = 0
    device_state: str = "disconnected"
    patient_name: str = ""
    sensor_started: datetime | None = None
    days_remaining: float | None = None


def _checksum(data: bytes) -> int:
    return (-sum(data)) & 0xFF


class SibionicsCGMCoordinator(DataUpdateCoordinator[SibionicsCGMData]):
    """Coordinate BLE communication and data updates for SIBIONICS CGM."""

    def __init__(
        self,
        hass: HomeAssistant,
        address: str,
        name: str,
        sensitivity_input: str,
        variant: str = "eu",
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"SIBIONICS CGM ({name})",
            update_interval=None,  # Push-based, not polling
        )
        self._address = address
        self._name = name
        self._sensitivity_input = sensitivity_input
        self._variant = variant

        self._client: BleakClient | None = None
        self._connected = False
        self._connecting = False  # Guard against thundering herd
        self._mac_reversed: bytes = b""
        self._glucose_index = 0
        self._last_received_index = -1  # highest index we've calibrated
        self._state = "init"
        self._response_event = asyncio.Event()
        self._readings: dict[int, GlucoseReading] = {}
        self._history_done = False

        # Queue for ordered calibration of incoming readings
        self._pending_readings: list[tuple[int, datetime, float, float]] = []
        self._processing_lock = asyncio.Lock()
        self._batch_tasks: set[asyncio.Task] = set()

        # Emulator (initialized lazily in executor)
        self._engine: Any = None
        self._engine_ready = False

        # Connection management
        self._connect_lock = asyncio.Lock()
        self._cancel_ble_callback: CALLBACK_TYPE | None = None
        self._enabled = True

        # Persistent storage for readings across HA restarts
        self._store = Store[dict](
            hass, 1, f"{DOMAIN}.{address.replace(':', '_')}"
        )

        # Data state
        self.data = SibionicsCGMData()

        # Entity ID for historical state writing (set by sensor platform)
        self._glucose_entity_id: str | None = None

        # Track last timestamp written to recorder to avoid duplicates
        # on reconnect (device replays history we already wrote)
        self._last_written_ts: float = 0.0
        # Index-based dedup: the sensor sends overlapping index ranges
        # with sub-second ts_base differences on reconnect, so timestamp
        # comparison alone misses duplicates. Track every index we wrote.
        self._written_indices: set[int] = set()
        # Track indices already passed to the ARM64 calibration engine.
        # The algorithm's Kalman filter is stateful — re-feeding an index
        # corrupts filter state and causes progressive calibration drift.
        self._calibrated_indices: set[int] = set()

    @property
    def address(self) -> str:
        return self._address

    @property
    def ble_enabled(self) -> bool:
        return self._enabled

    async def async_load_data(self) -> None:
        """Load persisted readings from disk."""
        stored = await self._store.async_load()
        if not stored:
            return

        _LOGGER.info("Restoring %d persisted readings", len(stored.get("readings", [])))
        for r in stored.get("readings", []):
            try:
                reading = GlucoseReading(
                    index=r["index"],
                    timestamp=datetime.fromisoformat(r["timestamp"]),
                    glucose_mmol=r["glucose_mmol"],
                    glucose_mgdl=r["glucose_mgdl"],
                    raw_mmol=r["raw_mmol"],
                    temperature=r["temperature"],
                    trend=r.get("trend", "stable"),
                )
                self._readings[reading.index] = reading
                if reading.index > self._last_received_index:
                    self._last_received_index = reading.index
                if reading.index >= self._glucose_index:
                    self._glucose_index = reading.index + 1
            except (KeyError, ValueError) as exc:
                _LOGGER.debug("Skipping invalid stored reading: %s", exc)

        if self._readings:
            latest = max(self._readings.values(), key=lambda r: r.index)
            self.data = SibionicsCGMData(
                glucose_mmol=latest.glucose_mmol,
                glucose_mgdl=latest.glucose_mgdl,
                raw_mmol=latest.raw_mmol,
                temperature=latest.temperature,
                trend=latest.trend,
                last_reading_time=latest.timestamp,
                reading_count=len(self._readings),
                device_state="disconnected",
                patient_name=self.data.patient_name,
            )
            # Restore _last_written_ts so history writes are not duplicated
            # across HA restarts. Without this, every restart replays and
            # re-writes the full history to the recorder.
            self._last_written_ts = stored.get("last_written_ts", 0.0)

    async def async_save_data(self) -> None:
        """Persist readings to disk."""
        # Keep last 1440 readings (24 hours at 1/min) to avoid unbounded growth
        recent = sorted(self._readings.values(), key=lambda r: r.index)[-MAX_READINGS_IN_MEMORY:]
        data = {
            "readings": [
                {
                    "index": r.index,
                    "timestamp": r.timestamp.isoformat(),
                    "glucose_mmol": r.glucose_mmol,
                    "glucose_mgdl": r.glucose_mgdl,
                    "raw_mmol": r.raw_mmol,
                    "temperature": r.temperature,
                    "trend": r.trend,
                }
                for r in recent
            ],
            "last_written_ts": self._last_written_ts,
        }
        await self._store.async_save(data)

    async def async_setup(self) -> None:
        """Initialize emulator and start BLE monitoring."""
        # Load persisted readings first (provides last_received_index for reconnect)
        await self.async_load_data()

        # Initialize emulator in executor (CPU-heavy)
        self.data = replace(self.data, device_state="initializing")
        self.async_set_updated_data(self.data)

        try:
            await self.hass.async_add_executor_job(self._init_emulator)
        except Exception as exc:
            _LOGGER.error("Failed to initialize calibration engine: %s", exc)
            self.data = replace(self.data, device_state="emulator_error")
            self.async_set_updated_data(self.data)
            raise

        self.data = replace(self.data, device_state="disconnected")
        self.async_set_updated_data(self.data)

        # Register BLE callback for when device appears
        self.hass.async_create_task(self._async_start_monitor())

    def _init_emulator(self) -> None:
        """Initialize the ARM64 calibration engine (runs in executor)."""
        from .emulator import CalibrationEngine

        self._engine = CalibrationEngine()
        self._engine.setup()
        self._engine.initialize(self._sensitivity_input)
        self._engine_ready = True
        _LOGGER.debug("Calibration engine ready (input=%s)", self._sensitivity_input)

    def _calibrate(self, raw_mmol: float, temperature: float, index: int) -> float:
        """Run a reading through the calibration algorithm (executor)."""
        if not self._engine_ready:
            return raw_mmol
        try:
            return self._engine.process(raw_mmol, temperature, index)
        except Exception as exc:
            _LOGGER.error(
                "Calibration engine error at index %d: %s — falling back to raw value",
                index, exc,
            )
            self._engine_ready = False
            # Schedule re-initialization
            self.hass.loop.call_soon_threadsafe(
                lambda: self.hass.async_create_task(self._async_reinit_emulator())
            )
            return raw_mmol

    async def _async_reinit_emulator(self) -> None:
        """Re-initialize calibration engine after a crash."""
        _LOGGER.warning("Re-initializing calibration engine after error")
        try:
            await self.hass.async_add_executor_job(self._init_emulator)
            _LOGGER.info("Calibration engine re-initialized successfully")
        except Exception as exc:
            _LOGGER.error("Failed to re-initialize calibration engine: %s", exc)
            self.data = replace(self.data, device_state="calibration_error")
            self.async_set_updated_data(self.data)

    async def _async_start_monitor(self) -> None:
        """Start BLE connection monitoring."""
        # Register callback for BLE advertisements
        self._cancel_ble_callback = bluetooth.async_register_callback(
            self.hass,
            self._handle_bluetooth_event,
            BluetoothCallbackMatcher(address=self._address, connectable=True),
            bluetooth.BluetoothScanningMode.ACTIVE,
        )

        # Try immediate connection
        self._safe_create_task(self._async_connect_and_run())

    @callback
    def _handle_bluetooth_event(
        self,
        service_info: bluetooth.BluetoothServiceInfoBleak,
        change: bluetooth.BluetoothChange,
    ) -> None:
        """Handle BLE advertisement callback."""
        if not self._enabled or self._connected or self._connecting:
            return
        _LOGGER.debug("BLE advertisement from %s, attempting connection", self._address)
        self._safe_create_task(self._async_connect_and_run())

    def _safe_create_task(self, coro: Any) -> asyncio.Task:
        """Create a background task with exception logging.

        Uses async_create_background_task so long-running data processing
        (history burst with 600+ readings) does not block HA startup.
        """

        async def _wrapper() -> None:
            try:
                await coro
            except Exception:
                _LOGGER.exception("Task failed unexpectedly")

        return self.hass.async_create_background_task(
            _wrapper(), f"sibionics_cgm_{self._address}"
        )

    async def _async_connect_and_run(self) -> None:
        """Connect to sensor and start data retrieval."""
        if not self._enabled:
            return

        self._connecting = True
        try:
            async with self._connect_lock:
                if self._connected:
                    return

                try:
                    await self._connect()
                    await self._authenticate()
                    await self._start_data_stream()
                except Exception as exc:
                    _LOGGER.warning("Connection failed: %s", exc)
                    self._connected = False
                    self.data = replace(
                        self.data,
                        connected=False,
                        device_state="connection_failed",
                    )
                    self.async_set_updated_data(self.data)
                    await self._disconnect()
                    # Schedule reconnect after failure
                    if self._enabled:
                        self.hass.loop.call_later(
                            RECONNECT_INTERVAL,
                            lambda: self._safe_create_task(self._async_connect_and_run()),
                        )
                    return

                # _start_data_stream exited normally (timeout / no data)
                # Force disconnect and schedule reconnect
                if self._connected:
                    _LOGGER.warning("Data stream ended, forcing disconnect and reconnect")
                    await self._disconnect()
                    self.data = replace(self.data, connected=False, device_state="disconnected")
                    self.async_set_updated_data(self.data)
                    if self._enabled:
                        self.hass.loop.call_later(
                            RECONNECT_INTERVAL,
                            lambda: self._safe_create_task(self._async_connect_and_run()),
                        )
        finally:
            self._connecting = False

    async def _connect(self) -> None:
        """Establish BLE connection."""
        self.data = replace(self.data, device_state="connecting")
        self.async_set_updated_data(self.data)

        ble_device = bluetooth.async_ble_device_from_address(
            self.hass, self._address, connectable=True
        )
        if ble_device is None:
            raise BleakError(f"Device {self._address} not available")

        self._client = await establish_connection(
            BleakClient,
            ble_device,
            self._address,
            disconnected_callback=self._on_disconnect,
            max_attempts=2,
        )

        self._connected = True
        self._mac_reversed = parse_mac_address(self._address)

        # Read device info
        await self._read_device_info()

        _LOGGER.info("Connected to %s (%s)", self._name, self._address)

    async def _read_device_info(self) -> None:
        """Read standard GATT device info characteristics."""
        from .const import CHAR_BATTERY, CHAR_FIRMWARE, CHAR_MODEL, CHAR_SERIAL

        for char_uuid, attr in [
            (CHAR_MODEL, "model"),
            (CHAR_SERIAL, "serial"),
            (CHAR_FIRMWARE, "firmware"),
            (CHAR_BATTERY, "battery"),
        ]:
            try:
                val = await self._client.read_gatt_char(char_uuid)
                if attr == "battery":
                    setattr(self.data, attr, val[0])
                else:
                    setattr(self.data, attr, val.decode("utf-8", errors="replace").strip("\x00"))
            except Exception:
                pass

    def _on_disconnect(self, client: BleakClient) -> None:
        """Handle BLE disconnection (called from bleak thread)."""
        # Marshal onto the event loop — bleak calls this from a background thread
        self.hass.loop.call_soon_threadsafe(self._handle_disconnect_sync)

    @callback
    def _handle_disconnect_sync(self) -> None:
        """Handle BLE disconnection on the event loop."""
        _LOGGER.info("Disconnected from %s", self._address)
        self._connected = False
        self._client = None
        self._history_done = False  # Reset so reconnect waits for history burst
        self.data = replace(
            self.data,
            connected=False,
            device_state="disconnected",
        )
        self.async_set_updated_data(self.data)

        # Schedule reconnect
        if self._enabled:
            self.hass.loop.call_later(
                RECONNECT_INTERVAL,
                lambda: self._safe_create_task(self._async_connect_and_run()),
            )

    async def _disconnect(self) -> None:
        """Disconnect BLE client."""
        if self._client:
            try:
                await self._client.disconnect()
            except Exception:
                pass
            self._client = None
        self._connected = False

    async def _authenticate(self) -> None:
        """Run the full auth + activate + time sync + data request sequence."""
        if not self._client or not self._client.is_connected:
            raise BleakError("Not connected")

        self._state = "init"
        await self._client.start_notify(NOTIFY_CHAR_UUID, self._on_notify)

        # AUTH
        _LOGGER.debug("Sending AUTH")
        auth_pkt = make_auth_packet(self._mac_reversed, self._variant)
        await self._client.write_gatt_char(WRITE_CHAR_UUID, auth_pkt, response=False)
        if not await self._wait_response(10.0) or self._state != "auth_ok":
            raise BleakError(f"Authentication failed: {self._state}")

        # ACTIVATE
        _LOGGER.debug("Sending ACTIVATE")
        ts = int(time.time())
        await self._client.write_gatt_char(
            WRITE_CHAR_UUID, make_activation_packet(ts), response=False
        )
        await self._wait_response(10.0)

        # TIME_SYNC + DATA_REQUEST (back-to-back like official app)
        # The calibration algorithm has stateful filters (Kalman, IIR biquad,
        # deconvolution) that need sequential data to converge.
        # - Fresh emulator (after HA restart): request from 0 to warm up filters
        # - Reconnect (emulator state preserved): request from last index to catch up
        if self._engine and self._engine._reading_index > 0:
            # Emulator has processed data this session — just catch up
            request_from = self._last_received_index + 1 if self._last_received_index >= 0 else 0
        else:
            # Fresh emulator — need full history for filter convergence
            request_from = 0
        _LOGGER.debug(
            "Sending TIME_SYNC + DATA_REQUEST(idx=%d) [last_received=%d]",
            request_from, self._last_received_index,
        )
        ts = int(time.time())
        await self._client.write_gatt_char(
            WRITE_CHAR_UUID, make_time_sync_packet(ts), response=False
        )
        await self._client.write_gatt_char(
            WRITE_CHAR_UUID, make_data_request_packet(request_from), response=False
        )

        self.data = replace(
            self.data,
            connected=True,
            device_state="authenticated",
        )
        self.async_set_updated_data(self.data)

    async def _start_data_stream(self) -> None:
        """Wait for history burst then live readings."""
        _LOGGER.debug("Waiting for glucose data stream")
        no_data_count = 0
        while no_data_count < 5 and self._connected and self._enabled:
            if await self._wait_response(30.0):
                no_data_count = 0
            else:
                no_data_count += 1
                if not self._history_done and self._readings:
                    # Wait for all in-flight batch processing to finish
                    # before declaring history complete — batches that
                    # reach the branch check after _history_done flips
                    # would skip _write_historical_states entirely.
                    if self._batch_tasks:
                        await asyncio.gather(
                            *self._batch_tasks, return_exceptions=True
                        )
                    self._history_done = True
                    _LOGGER.info(
                        "History complete: %d readings, waiting for live data",
                        len(self._readings),
                    )
                    # Flush historical readings to HA now that all
                    # calibration is done. Values in self._readings
                    # are final (Kalman filter converged).
                    await self._flush_historical_states()
                    # Push state once now so entities show the latest
                    # calibrated value while waiting for first live reading
                    self.async_set_updated_data(self.data)

    def _on_notify(self, sender: Any, data: bytearray) -> None:
        """Handle incoming BLE notifications (called from bleak thread)."""
        # Marshal onto the event loop — bleak calls this from a background thread
        raw = bytes(data)
        self.hass.loop.call_soon_threadsafe(self._handle_notify_sync, raw)

    @callback
    def _handle_notify_sync(self, raw: bytes) -> None:
        """Handle incoming BLE notification on the event loop."""
        dec = decrypt_response(raw)
        pkt_type = dec[1] if len(dec) > 1 else 0

        # 5-byte command acknowledgment
        if len(dec) == 5:
            code = dec[2]
            chk_ok = dec[4] == _checksum(dec[:4])
            if not chk_ok:
                _LOGGER.warning("Command packet checksum failed (type=0x%02x)", pkt_type)
                return
            if pkt_type == 0x01:
                self._state = "auth_ok" if code == 1 else "auth_fail"
            elif pkt_type == 0x07:
                self._state = "activated"
            elif pkt_type == 0x03:
                self._state = "time_ok"
            elif pkt_type == 0x08:
                self._state = "data_ack"
            self._response_event.set()
            return

        # Glucose data notification
        if pkt_type == 0x08 and len(dec) >= 9:
            # Verify checksum on glucose data packets
            if len(dec) > 1:
                pkt_chk = dec[-1]
                expected_chk = _checksum(dec[:-1])
                if pkt_chk != expected_chk:
                    _LOGGER.warning(
                        "Glucose data checksum failed (got=0x%02x expected=0x%02x, len=%d)",
                        pkt_chk, expected_chk, len(dec),
                    )
                    # Still process — some firmware may not use trailing checksum
                    # but log the event for monitoring

            count = dec[2]
            start_idx = struct.unpack("<H", dec[3:5])[0]
            ts_base = struct.unpack("<I", dec[5:9])[0]

            batch: list[tuple[int, datetime, float, float]] = []
            for i in range(count):
                off = 9 + i * 8
                if off + 8 > len(dec):
                    break
                rec = dec[off:off + 8]
                raw_glucose = rec[4] / 10.0
                temp_raw = struct.unpack("<H", rec[0:2])[0]
                temperature = temp_raw / 10.0
                idx = start_idx + i
                reading_time = datetime.fromtimestamp(
                    ts_base + i * 60, tz=timezone.utc
                )

                # Validate raw glucose range
                if raw_glucose < RAW_GLUCOSE_MIN or raw_glucose > RAW_GLUCOSE_MAX:
                    _LOGGER.warning(
                        "Raw glucose %.1f mmol/L out of range at idx %d, skipping",
                        raw_glucose, idx,
                    )
                    continue

                # Validate temperature range
                if temperature < TEMP_MIN or temperature > TEMP_MAX:
                    _LOGGER.warning(
                        "Temperature %.1f°C out of range at idx %d, skipping",
                        temperature, idx,
                    )
                    continue

                batch.append((idx, reading_time, raw_glucose, temperature))

                if idx >= self._glucose_index:
                    self._glucose_index = idx + 1

            if batch:
                # Process all readings in this packet in order (critical for
                # the algorithm's Kalman filter to converge correctly).
                task = self._safe_create_task(
                    self._async_process_batch(batch)
                )
                self._batch_tasks.add(task)
                task.add_done_callback(self._batch_tasks.discard)

            self._state = "data_received"
            self._response_event.set()
            return

        self._response_event.set()

    async def _async_process_batch(
        self,
        batch: list[tuple[int, datetime, float, float]],
    ) -> None:
        """Calibrate a batch of readings sequentially and push updates.

        The algorithm's internal filters (Kalman, IIR biquad, deconvolution)
        are stateful and require sequential feeding. We process all readings
        in index order under a lock to prevent interleaving from concurrent
        notification packets.
        """
        async with self._processing_lock:
            # Sort batch by index to ensure correct order
            batch.sort(key=lambda x: x[0])
            _LOGGER.debug(
                "Processing batch: %d readings, idx %d-%d",
                len(batch), batch[0][0], batch[-1][0],
            )

            for index, reading_time, raw_mmol, temperature in batch:
                # Skip indices already calibrated — the ARM64 algorithm's
                # Kalman filter is stateful and re-feeding an index corrupts
                # its internal state, causing progressive calibration drift.
                if index in self._calibrated_indices:
                    continue

                # Calibrate in executor (CPU-heavy ARM64 emulation)
                cal_mmol = await self.hass.async_add_executor_job(
                    self._calibrate, raw_mmol, temperature, index
                )
                self._calibrated_indices.add(index)

                # Validate calibrated output
                if not math.isfinite(cal_mmol) or cal_mmol < 0:
                    _LOGGER.warning(
                        "Invalid calibrated value %.4f at idx %d, skipping",
                        cal_mmol, index,
                    )
                    continue

                # 0.0 is normal during algorithm warm-up (Kalman filter convergence).
                # Skip these — only show real calibrated values (patient safety).
                if cal_mmol == 0.0:
                    if index > self._last_received_index:
                        self._last_received_index = index
                    continue

                cal_mgdl = mmol_to_mgdl(cal_mmol)

                # Validate calibrated mg/dL range
                if cal_mgdl < CAL_MGDL_MIN or cal_mgdl > CAL_MGDL_MAX:
                    _LOGGER.warning(
                        "Calibrated %d mg/dL out of range at idx %d, skipping",
                        cal_mgdl, index,
                    )
                    continue

                # Track highest index we've processed
                if index > self._last_received_index:
                    self._last_received_index = index

                # Calculate trend from recent readings
                trend = self._calculate_trend(cal_mmol)

                reading = GlucoseReading(
                    index=index,
                    timestamp=reading_time,
                    glucose_mmol=round(cal_mmol, 1),
                    glucose_mgdl=cal_mgdl,
                    raw_mmol=raw_mmol,
                    temperature=temperature,
                    trend=trend,
                )
                self._readings[index] = reading

            # Trim in-memory readings to prevent unbounded growth
            if len(self._readings) > MAX_READINGS_IN_MEMORY:
                sorted_keys = sorted(self._readings.keys())
                for k in sorted_keys[:-MAX_READINGS_IN_MEMORY]:
                    del self._readings[k]
                # Keep _calibrated_indices in sync
                keep = set(self._readings.keys())
                self._calibrated_indices &= keep

            # After processing the entire batch, update internal state
            if not self._readings:
                return

            latest = max(self._readings.values(), key=lambda r: r.index)
            earliest = min(self._readings.values(), key=lambda r: r.index)

            # Track sensor start time from earliest reading
            sensor_started = self.data.sensor_started or earliest.timestamp
            now = datetime.now(timezone.utc)
            elapsed = (now - sensor_started).total_seconds() / 86400
            days_remaining = round(max(14.0 - elapsed, 0.0), 1)

            self.data = SibionicsCGMData(
                connected=self._connected,
                glucose_mmol=latest.glucose_mmol,
                glucose_mgdl=latest.glucose_mgdl,
                raw_mmol=latest.raw_mmol,
                temperature=latest.temperature,
                trend=latest.trend,
                battery=self.data.battery,
                firmware=self.data.firmware,
                serial=self.data.serial,
                model=self.data.model,
                last_reading_time=latest.timestamp,
                reading_count=len(self._readings),
                device_state="receiving",
                patient_name=self.data.patient_name,
                sensor_started=sensor_started,
                days_remaining=days_remaining,
            )

            if self._history_done:
                # Live mode — push to HA every 5 minutes only
                if latest.index % 5 == 0:
                    # Only push to entity state if the reading is recent.
                    # Stale readings (from late-arriving history batches
                    # processed after _history_done flipped) would inject
                    # phantom values into entity state and corrupt statistics.
                    age = time.time() - latest.timestamp.timestamp()
                    if age < 600:  # 10 minutes
                        self.async_set_updated_data(self.data)
                        _LOGGER.info(
                            "LIVE #%d: %d mg/dL (%.1f mmol/L) at %s",
                            latest.index, latest.glucose_mgdl, latest.glucose_mmol,
                            latest.timestamp.strftime("%H:%M"),
                        )
                    else:
                        _LOGGER.debug(
                            "Skipping stale reading #%d (age %.0fs) in live mode",
                            latest.index, age,
                        )
            else:
                # History burst — just calibrate and store readings.
                # Do NOT write to HA yet: the Kalman filter needs all
                # overlapping packets to converge. Writing now produces
                # values 5-8 mg/dL too low. The correct values are
                # flushed in _flush_historical_states after all batches
                # complete.
                if len(batch) > 1:
                    _LOGGER.debug(
                        "History burst: %d readings (idx %d-%d), latest: %d mg/dL",
                        len(batch), batch[0][0], batch[-1][0], latest.glucose_mgdl,
                    )

            # Persist readings to survive HA restarts
            await self.async_save_data()

    def _calculate_trend(self, current_mmol: float) -> str:
        """Calculate glucose trend from recent readings."""
        if len(self._readings) < 3:
            return "stable"

        recent = sorted(self._readings.values(), key=lambda r: r.index)[-15:]
        if len(recent) < 3:
            return "stable"

        # Use actual index span for rate calculation (not count)
        oldest = recent[0].glucose_mmol
        newest = current_mmol
        delta = newest - oldest
        index_span = recent[-1].index - recent[0].index
        if index_span <= 0:
            return "stable"
        rate = delta / index_span  # mmol/L per minute (1 index = 1 minute)

        if rate > 0.15:
            return "rapid_rise"
        elif rate > 0.07:
            return "rising"
        elif rate > 0.03:
            return "slow_rise"
        elif rate < -0.15:
            return "rapid_fall"
        elif rate < -0.07:
            return "falling"
        elif rate < -0.03:
            return "slow_fall"
        return "stable"

    async def _flush_historical_states(self) -> None:
        """Write finalized historical readings to HA recorder.

        Called once after all history batches are calibrated and
        _history_done is True. Values in self._readings are final
        (Kalman filter has converged on overlapping packets), so they
        match FHIR. Writes every 5th reading with device timestamps.
        """
        if not self._glucose_entity_id:
            return

        written = 0
        for index in sorted(self._readings):
            if index % 5 != 0:
                continue
            if index in self._written_indices:
                continue

            reading = self._readings[index]
            ts = reading.timestamp.timestamp()

            if ts <= self._last_written_ts:
                continue

            self.hass.states.async_set(
                self._glucose_entity_id,
                str(reading.glucose_mgdl),
                attributes={
                    "unit_of_measurement": "mg/dL",
                    "state_class": "measurement",
                    "icon": "mdi:diabetes",
                    "friendly_name": f"{self._name} Glucose",
                },
                force_update=True,
                context=Context(id=ulid_at_time(ts)),
                timestamp=ts,
            )
            self._last_written_ts = ts
            self._written_indices.add(index)
            written += 1

        if written:
            _LOGGER.info("Flushed %d historical readings to HA recorder", written)
            await self.async_save_data()

    async def _wait_response(self, timeout: float = 10.0) -> bool:
        """Wait for a response from the sensor."""
        self._response_event.clear()
        try:
            await asyncio.wait_for(self._response_event.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            return False

    async def async_disable_connection(self) -> None:
        """Disable BLE connection."""
        self._enabled = False
        # Unregister BLE callback to prevent stale references
        if self._cancel_ble_callback:
            self._cancel_ble_callback()
            self._cancel_ble_callback = None
        await self._disconnect()
        self.data = replace(
            self.data,
            connected=False,
            device_state="disabled",
        )
        self.async_set_updated_data(self.data)

    async def async_enable_connection(self) -> None:
        """Enable BLE connection."""
        self._enabled = True
        self.data = replace(self.data, device_state="disconnected")
        self.async_set_updated_data(self.data)
        self._safe_create_task(self._async_connect_and_run())
