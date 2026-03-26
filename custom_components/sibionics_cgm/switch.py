"""Switch entity for SIBIONICS CGM integration — BLE connection control."""

from __future__ import annotations

from homeassistant.components.switch import SwitchEntity
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
    """Set up SIBIONICS CGM switches."""
    coordinator: SibionicsCGMCoordinator = entry.runtime_data
    address = entry.data[CONF_ADDRESS]
    name = entry.data.get(CONF_NAME, address)

    async_add_entities([
        SibionicsCGMConnectionSwitch(coordinator, address, name),
    ])


class SibionicsCGMConnectionSwitch(
    CoordinatorEntity[SibionicsCGMCoordinator], SwitchEntity
):
    """Switch to enable/disable BLE connection to the CGM sensor."""

    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_entity_category = EntityCategory.CONFIG
    _attr_name = "BLE Connection"
    _attr_icon = "mdi:bluetooth"

    def __init__(
        self,
        coordinator: SibionicsCGMCoordinator,
        address: str,
        name: str,
    ) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{address}-ble-connection-switch"
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
        return self.coordinator.ble_enabled

    async def async_turn_on(self, **kwargs) -> None:
        """Enable BLE connection."""
        await self.coordinator.async_enable_connection()

    async def async_turn_off(self, **kwargs) -> None:
        """Disable BLE connection."""
        await self.coordinator.async_disable_connection()

    @callback
    def _handle_coordinator_update(self) -> None:
        self.async_write_ha_state()
