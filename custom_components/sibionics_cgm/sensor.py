"""Sensor entities for SIBIONICS CGM integration."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_ADDRESS,
    CONF_NAME,
    PERCENTAGE,
    UnitOfTemperature,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from .const import DATA_STALE_TIMEOUT, DOMAIN, MANUFACTURER, MODEL, TREND_ICONS
from .coordinator import SibionicsCGMCoordinator, SibionicsCGMData

_LOGGER = logging.getLogger(__name__)


SENSOR_DESCRIPTIONS = [
    SensorEntityDescription(
        key="glucose_mgdl",
        name="Glucose",
        native_unit_of_measurement="mg/dL",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:diabetes",
    ),
    SensorEntityDescription(
        key="glucose_mmol",
        name="Glucose (mmol/L)",
        native_unit_of_measurement="mmol/L",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:diabetes",
        entity_registry_enabled_default=False,
    ),
    SensorEntityDescription(
        key="trend",
        name="Glucose Trend",
        icon="mdi:arrow-right",
    ),
    SensorEntityDescription(
        key="temperature",
        name="Sensor Temperature",
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        device_class=SensorDeviceClass.TEMPERATURE,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
    ),
    SensorEntityDescription(
        key="raw_mmol",
        name="Raw Glucose",
        native_unit_of_measurement="mmol/L",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:chart-line",
        entity_registry_enabled_default=False,
    ),
    SensorEntityDescription(
        key="battery",
        name="Battery",
        native_unit_of_measurement=PERCENTAGE,
        device_class=SensorDeviceClass.BATTERY,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    SensorEntityDescription(
        key="last_reading_time",
        name="Last Reading",
        device_class=SensorDeviceClass.TIMESTAMP,
        icon="mdi:clock-outline",
    ),
    SensorEntityDescription(
        key="reading_count",
        name="Reading Count",
        state_class=SensorStateClass.TOTAL_INCREASING,
        icon="mdi:counter",
        entity_registry_enabled_default=False,
    ),
    SensorEntityDescription(
        key="device_state",
        name="Device State",
        icon="mdi:bluetooth",
        entity_registry_enabled_default=False,
    ),
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up SIBIONICS CGM sensors."""
    coordinator: SibionicsCGMCoordinator = entry.runtime_data
    address = entry.data[CONF_ADDRESS]
    name = entry.data.get(CONF_NAME, address)

    entities = [
        SibionicsCGMSensor(coordinator, description, address, name)
        for description in SENSOR_DESCRIPTIONS
    ]
    async_add_entities(entities)


class SibionicsCGMSensor(
    CoordinatorEntity[SibionicsCGMCoordinator], SensorEntity
):
    """A sensor entity for SIBIONICS CGM data."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(
        self,
        coordinator: SibionicsCGMCoordinator,
        description: SensorEntityDescription,
        address: str,
        name: str,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{address}-{description.key}"
        self._address = address
        self._device_name = name

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, self._address)},
            name=self._device_name,
            manufacturer=MANUFACTURER,
            model=MODEL,
            sw_version=self.coordinator.data.firmware,
        )

    @property
    def available(self) -> bool:
        key = self.entity_description.key
        # Battery and device_state are always available (diagnostic)
        if key in ("battery", "device_state"):
            return True
        # Other sensors need at least one reading AND data must not be stale
        data = self.coordinator.data
        if data.glucose_mgdl is None:
            return False
        # Check staleness — mark unavailable if no reading for DATA_STALE_TIMEOUT
        if data.last_reading_time is not None:
            now = dt_util.utcnow()
            last = data.last_reading_time
            # Handle naive datetimes from legacy persisted data
            if last.tzinfo is None:
                last = last.replace(tzinfo=dt_util.UTC)
            age = (now - last).total_seconds()
            if age > DATA_STALE_TIMEOUT:
                return False
        return True

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle data update from coordinator."""
        data = self.coordinator.data
        key = self.entity_description.key

        if key == "glucose_mgdl":
            self._attr_native_value = data.glucose_mgdl
            # Add history as state attributes
            if data.history:
                recent = data.history[-10:]
                self._attr_extra_state_attributes = {
                    "history": [
                        {
                            "time": r.timestamp.isoformat(),
                            "mgdl": r.glucose_mgdl,
                            "mmol": r.glucose_mmol,
                        }
                        for r in recent
                    ]
                }
        elif key == "glucose_mmol":
            self._attr_native_value = data.glucose_mmol
        elif key == "trend":
            self._attr_native_value = data.trend
            self._attr_icon = TREND_ICONS.get(data.trend, "mdi:arrow-right")
        elif key == "temperature":
            self._attr_native_value = data.temperature
        elif key == "raw_mmol":
            self._attr_native_value = data.raw_mmol
        elif key == "battery":
            self._attr_native_value = data.battery
        elif key == "last_reading_time":
            self._attr_native_value = data.last_reading_time
        elif key == "reading_count":
            self._attr_native_value = data.reading_count
        elif key == "device_state":
            self._attr_native_value = data.device_state

        self.async_write_ha_state()
