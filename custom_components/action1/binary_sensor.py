"""Binary sensors for Action1."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import Action1ConfigEntry
from .coordinator import Endpoint
from .entity import Action1EndpointEntity, add_endpoint_entities


@dataclass(frozen=True, kw_only=True)
class Action1BinarySensorDescription(BinarySensorEntityDescription):
    value_fn: Callable[[Endpoint], bool | None]


BINARY_SENSORS: tuple[Action1BinarySensorDescription, ...] = (
    Action1BinarySensorDescription(
        key="reboot_required",
        value_fn=lambda e: e.reboot_required,
    ),
    Action1BinarySensorDescription(
        key="connected",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda e: e.connected,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: Action1ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    add_endpoint_entities(
        coordinator,
        async_add_entities,
        lambda endpoint_id: (
            Action1BinarySensor(coordinator, endpoint_id, description)
            for description in BINARY_SENSORS
        ),
    )


class Action1BinarySensor(Action1EndpointEntity, BinarySensorEntity):
    """A yes/no value from the PC's record in the last poll."""

    entity_description: Action1BinarySensorDescription

    def __init__(
        self, coordinator, endpoint_id: str, description: Action1BinarySensorDescription
    ) -> None:
        super().__init__(coordinator, endpoint_id, description.key)
        self.entity_description = description

    @property
    def is_on(self) -> bool | None:
        return self.entity_description.value_fn(self.endpoint)
