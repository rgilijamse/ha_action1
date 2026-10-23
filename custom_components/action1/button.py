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
    """Poll Action1 now instead of waiting for the hourly poll. Read-only."""

    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator, "refresh")

    @property
    def available(self) -> bool:
        # Usable to retry while polls fail.
        return True

    async def async_press(self) -> None:
        await self.coordinator.async_request_refresh()
