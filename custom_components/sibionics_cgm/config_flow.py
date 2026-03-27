"""Config flow for SIBIONICS CGM integration.

Two entry paths:
1. BLE discovery: HA detects the sensor, user confirms and enters QR code.
2. Manual setup: user enters QR code, we scan for matching sensor.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import voluptuous as vol
from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.const import CONF_ADDRESS, CONF_NAME

from .const import (
    CONF_BLE_MATCH_KEY,
    CONF_PATIENT_NAME,
    CONF_QR_CODE,
    CONF_SENSITIVITY_INPUT,
    CONF_SENSOR_SERIAL,
    CONF_VARIANT,
    DOMAIN,
    SERVICE_UUID,
)

_LOGGER = logging.getLogger(__name__)


def parse_qr_code(qr_data: str) -> dict[str, str]:
    """Extract sensor parameters from GS1 QR code data.

    QR format: (01)06972831641063(11)250805(17)270204(10)LT48250770N(21)250770QF32450CAA59

    AI 21 serial (e.g. 250770QF32450CAA59):
      - serial[6:10] = "QF32" -> BLE match key (last 4 chars of device name)
      - serial[6:14] = "QF32450C" -> sensitivity decryption input
    """
    # Extract AI 21 (serial number)
    match = re.search(r"\(21\)(\w+)", qr_data)
    if not match:
        # Try without parentheses (raw GS1 element string)
        # AI 21 is variable length, typically at end
        match = re.search(r"21(\w{10,})", qr_data)

    if not match:
        raise ValueError("QR code does not contain AI 21 (serial number)")

    serial = match.group(1)
    if len(serial) < 14:
        raise ValueError(f"Serial number too short: {serial} (need at least 14 chars)")

    ble_match_key = serial[6:10]       # e.g. "QF32"
    sensitivity_input = serial[6:14]   # e.g. "QF32450C"

    return {
        CONF_SENSOR_SERIAL: serial,
        CONF_BLE_MATCH_KEY: ble_match_key,
        CONF_SENSITIVITY_INPUT: sensitivity_input,
    }


def _device_matches_qr(name: str | None, ble_match_key: str) -> bool:
    """Check if a BLE device name ends with the QR-derived match key."""
    if not name:
        return False
    return name.upper().endswith(ble_match_key.upper())


class SibionicsCGMOptionsFlow(OptionsFlow):
    """Handle options for SIBIONICS CGM (edit patient name)."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage options."""
        if user_input is not None:
            new_name = user_input[CONF_PATIENT_NAME].strip()
            # Update config entry data with new patient name
            new_data = {**self.config_entry.data, CONF_PATIENT_NAME: new_name}
            self.hass.config_entries.async_update_entry(
                self.config_entry, data=new_data,
                title=f"SIBIONICS CGM — {new_name}" if new_name else f"SIBIONICS CGM ({new_data.get(CONF_NAME, '')})",
            )
            return self.async_create_entry(data={})

        current_name = self.config_entry.data.get(CONF_PATIENT_NAME, "")
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {vol.Required(CONF_PATIENT_NAME, default=current_name): str}
            ),
        )


class SibionicsCGMConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for SIBIONICS CGM."""

    VERSION = 1

    @staticmethod
    def async_get_options_flow(config_entry: ConfigEntry) -> SibionicsCGMOptionsFlow:
        """Get the options flow."""
        return SibionicsCGMOptionsFlow()

    def __init__(self) -> None:
        """Initialize flow."""
        self._discovery_info: bluetooth.BluetoothServiceInfoBleak | None = None
        self._qr_data: dict[str, str] = {}
        self._address: str = ""
        self._name: str = ""
        self._patient_name: str = ""

    async def async_step_bluetooth(
        self, discovery_info: bluetooth.BluetoothServiceInfoBleak
    ) -> ConfigFlowResult:
        """Handle BLE discovery."""
        _LOGGER.debug(
            "BLE discovery: %s (%s)", discovery_info.name, discovery_info.address
        )
        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()

        self._discovery_info = discovery_info
        self._address = discovery_info.address
        self._name = discovery_info.name or discovery_info.address

        return await self.async_step_qr_code()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle manual user setup — select from discovered devices."""
        if user_input is not None:
            address = user_input[CONF_ADDRESS]
            self._address = address
            await self.async_set_unique_id(address)
            self._abort_if_unique_id_configured()

            # Find device name from discovered services
            for info in bluetooth.async_discovered_service_info(self.hass):
                if info.address == address:
                    self._name = info.name or address
                    break

            return await self.async_step_qr_code()

        # List discovered SIBIONICS devices
        devices: dict[str, str] = {}
        for info in bluetooth.async_discovered_service_info(self.hass):
            if SERVICE_UUID in info.service_uuids:
                devices[info.address] = (
                    f"{info.name} ({info.address})" if info.name else info.address
                )

        if not devices:
            return self.async_abort(reason="no_devices_found")

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {vol.Required(CONF_ADDRESS): vol.In(devices)}
            ),
        )

    async def async_step_qr_code(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Collect QR code from sensor packaging."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._patient_name = user_input.get(CONF_PATIENT_NAME, "").strip()
            qr_raw = user_input[CONF_QR_CODE].strip()
            try:
                self._qr_data = parse_qr_code(qr_raw)
            except ValueError as exc:
                _LOGGER.warning("QR code parse error: %s", exc)
                errors["base"] = "invalid_qr_code"
            else:
                # Verify QR matches device (both discovery and manual paths)
                match_key = self._qr_data[CONF_BLE_MATCH_KEY]
                if not _device_matches_qr(self._name, match_key):
                    _LOGGER.warning(
                        "QR match key '%s' doesn't match device '%s'",
                        match_key, self._name,
                    )
                    errors["base"] = "qr_device_mismatch"

                if not errors:
                    return await self.async_step_confirm()

        return self.async_show_form(
            step_id="qr_code",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_PATIENT_NAME): str,
                    vol.Required(CONF_QR_CODE): str,
                }
            ),
            description_placeholders={"name": self._name},
            errors=errors,
        )

    async def async_step_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm setup."""
        if user_input is not None:
            title = f"SIBIONICS CGM — {self._patient_name}" if self._patient_name else f"SIBIONICS CGM ({self._name})"
            return self.async_create_entry(
                title=title,
                data={
                    CONF_ADDRESS: self._address,
                    CONF_NAME: self._name,
                    CONF_PATIENT_NAME: self._patient_name,
                    CONF_QR_CODE: self._qr_data.get(CONF_SENSOR_SERIAL, ""),
                    CONF_SENSOR_SERIAL: self._qr_data.get(CONF_SENSOR_SERIAL, ""),
                    CONF_SENSITIVITY_INPUT: self._qr_data.get(CONF_SENSITIVITY_INPUT, ""),
                    CONF_BLE_MATCH_KEY: self._qr_data.get(CONF_BLE_MATCH_KEY, ""),
                    CONF_VARIANT: "eu",
                },
            )

        return self.async_show_form(
            step_id="confirm",
            description_placeholders={
                "name": self._name,
                "patient_name": self._patient_name or "Not provided",
                "serial": self._qr_data.get(CONF_SENSOR_SERIAL, "unknown"),
                "sensitivity_input": self._qr_data.get(CONF_SENSITIVITY_INPUT, "unknown"),
            },
        )
