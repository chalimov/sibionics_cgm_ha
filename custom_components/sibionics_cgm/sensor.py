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
    EntityCategory,
    PERCENTAGE,
    UnitOfTemperature,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from .const import DOMAIN, MANUFACTURER, MODEL, TREND_ICONS
from .coordinator import SibionicsCGMCoordinator, SibionicsCGMData

_LOGGER = logging.getLogger(__name__)


SENSOR_DESCRIPTIONS = [
    SensorEntityDescription(
        key="glucose_mgdl",
        name="Glucose",
        native_unit_of_measurement="mg/dL",
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
        icon="mdi:diabetes",
    ),
    SensorEntityDescription(
        key="glucose_mmol",
        name="Glucose (mmol/L)",
        native_unit_of_measurement="mmol/L",
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
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
    SensorEntityDescription(
        key="patient_name",
        name="User",
        icon="mdi:account",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="days_remaining",
        name="Sensor Days Remaining",
        native_unit_of_measurement="d",
        icon="mdi:calendar-clock",
        suggested_display_precision=1,
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="sensor_started",
        name="Sensor Activated",
        device_class=SensorDeviceClass.TIMESTAMP,
        icon="mdi:calendar-start",
        entity_category=EntityCategory.DIAGNOSTIC,
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

    # Register glucose entity_id for historical state writing
    for entity in entities:
        if entity.entity_description.key == "glucose_mgdl":
            coordinator._glucose_entity_id = entity.entity_id
            break


class SibionicsCGMSensor(
    CoordinatorEntity[SibionicsCGMCoordinator], SensorEntity
):
    """A sensor entity for SIBIONICS CGM data."""

    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_force_update = True

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
        # Battery, device_state, patient_name always available
        if key in ("battery", "device_state", "patient_name"):
            return True
        # Days remaining / sensor started available once we have data
        if key in ("days_remaining", "sensor_started"):
            return self.coordinator.data.sensor_started is not None
        # Other sensors need at least one reading to be available
        # Once a reading exists, keep showing the last known value
        # (HA recorder needs continuous availability to build history graphs)
        return self.coordinator.data.glucose_mgdl is not None

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle data update from coordinator."""
        data = self.coordinator.data
        key = self.entity_description.key

        if key == "glucose_mgdl":
            self._attr_native_value = data.glucose_mgdl
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
        elif key == "patient_name":
            self._attr_native_value = data.patient_name or "Not set"
        elif key == "days_remaining":
            self._attr_native_value = data.days_remaining
        elif key == "sensor_started":
            self._attr_native_value = data.sensor_started

        self.async_write_ha_state()
