"""Refresh button for Action1."""
from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import Action1ConfigEntry
from .entity import Action1HubEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: Action1ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    async_add_entities([RefreshButton(entry.runtime_data)])


class RefreshButton(Action1HubEntity, ButtonEntity):
    """Poll Action1 now instead of waiting for the hourly poll and 6-hourly check. Read-only."""

    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator, "refresh")

    @property
    def available(self) -> bool:
        # Usable to retry while polls fail.
        return True

    async def async_press(self) -> None:
        await self.coordinator.async_request_refresh()
        # The known-exploited check takes ~60 calls; don't hold up the button press for it.
        self.coordinator.config_entry.async_create_background_task(
            self.hass, self.coordinator.kev.async_request_refresh(), "action1 refresh known-exploited CVEs"
        )
