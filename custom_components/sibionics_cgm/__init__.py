"""SIBIONICS CGM integration for Home Assistant.

Connects to a SIBIONICS GS1 continuous glucose monitor via BLE,
authenticates using the reverse-engineered RC4 protocol, and provides
medically accurate glucose readings via ARM64 emulation of the real
calibration algorithm.
"""

from __future__ import annotations

import logging

from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS, CONF_NAME, Platform
from homeassistant.core import HomeAssistant

from .const import CONF_PATIENT_NAME, CONF_SENSITIVITY_INPUT, CONF_VARIANT, DOMAIN
from .coordinator import SibionicsCGMCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.SENSOR, Platform.BINARY_SENSOR, Platform.SWITCH]

type SibionicsCGMConfigEntry = ConfigEntry[SibionicsCGMCoordinator]


async def async_setup_entry(
    hass: HomeAssistant, entry: SibionicsCGMConfigEntry
) -> bool:
    """Set up SIBIONICS CGM from a config entry."""
    address = entry.data[CONF_ADDRESS]
    name = entry.data.get(CONF_NAME, address)
    sensitivity_input = entry.data[CONF_SENSITIVITY_INPUT]
    variant = entry.data.get(CONF_VARIANT, "eu")

    coordinator = SibionicsCGMCoordinator(
        hass=hass,
        address=address,
        name=name,
        sensitivity_input=sensitivity_input,
        variant=variant,
    )
    entry.runtime_data = coordinator

    # Set patient name from config entry
    from dataclasses import replace
    coordinator.data = replace(
        coordinator.data,
        patient_name=entry.data.get(CONF_PATIENT_NAME, ""),
    )

    await coordinator.async_setup()
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Push restored data to entities now that they exist
    coordinator.async_set_updated_data(coordinator.data)

    return True


async def async_unload_entry(
    hass: HomeAssistant, entry: SibionicsCGMConfigEntry
) -> bool:
    """Unload a config entry."""
    coordinator: SibionicsCGMCoordinator = entry.runtime_data

    # Save readings and disable connection before unloading
    await coordinator.async_save_data()
    await coordinator.async_disable_connection()

    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
