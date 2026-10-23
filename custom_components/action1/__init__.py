"""Action1: patch state of the endpoints Action1 manages, as Home Assistant entities."""
from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.device_registry import DeviceEntry
from homeassistant.helpers.storage import Store

from .api import Action1Client
from .const import CONF_REGION, DOMAIN
from .coordinator import STORAGE_VERSION, Action1Coordinator

PLATFORMS = [Platform.BINARY_SENSOR, Platform.BUTTON, Platform.SENSOR]

type Action1ConfigEntry = ConfigEntry[Action1Coordinator]


async def async_setup_entry(hass: HomeAssistant, entry: Action1ConfigEntry) -> bool:
    """Set up Action1 from a config entry."""
    client = Action1Client(
        async_get_clientsession(hass),
        entry.data[CONF_REGION],
        entry.data[CONF_CLIENT_ID],
        entry.data[CONF_CLIENT_SECRET],
    )
    coordinator = Action1Coordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: Action1ConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_remove_entry(hass: HomeAssistant, entry: Action1ConfigEntry) -> None:
    """Delete the stored "since" timestamps with the entry."""
    await Store(hass, STORAGE_VERSION, f"{DOMAIN}.{entry.entry_id}").async_remove()


async def async_remove_config_entry_device(
    hass: HomeAssistant, entry: Action1ConfigEntry, device: DeviceEntry
) -> bool:
    """Allow removing a PC that left Action1 or moved to an ignored group."""
    coordinator = entry.runtime_data
    return not any(
        domain == DOMAIN and (key in coordinator.data or key == coordinator.org_id)
        for domain, key in device.identifiers
    )
