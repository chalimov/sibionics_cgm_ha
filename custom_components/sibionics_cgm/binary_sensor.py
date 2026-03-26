"""Binary sensor entities for SIBIONICS CGM integration."""

from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS, CONF_NAME, EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, MANUFACTURER, MODEL
from .coordinator import SibionicsCGMCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up SIBIONICS CGM binary sensors."""
    coordinator: SibionicsCGMCoordinator = entry.runtime_data
    address = entry.data[CONF_ADDRESS]
    name = entry.data.get(CONF_NAME, address)

    async_add_entities([
        SibionicsCGMConnectionSensor(coordinator, address, name),
    ])


class SibionicsCGMConnectionSensor(
    CoordinatorEntity[SibionicsCGMCoordinator], BinarySensorEntity
):
    """Binary sensor showing BLE connection status."""

    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_name = "Connection"

    def __init__(
        self,
        coordinator: SibionicsCGMCoordinator,
        address: str,
        name: str,
    ) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{address}-connection"
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
        return True

    @property
    def is_on(self) -> bool:
        return self.coordinator.data.connected

    @callback
    def _handle_coordinator_update(self) -> None:
        self.async_write_ha_state()
