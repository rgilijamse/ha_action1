"""Base entities for Action1."""
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from homeassistant.core import callback
from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import Action1Coordinator, Action1KevCoordinator, Endpoint


class Action1EndpointEntity(CoordinatorEntity[Action1Coordinator]):
    """An entity tied to one managed PC."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: Action1Coordinator, endpoint_id: str, key: str) -> None:
        super().__init__(coordinator)
        self._endpoint_id = endpoint_id
        self._attr_unique_id = f"{endpoint_id}_{key}"
        self._attr_translation_key = key
        self._attr_device_info = coordinator.data[endpoint_id].device_info

    @property
    def endpoint(self) -> Endpoint | None:
        return self.coordinator.data.get(self._endpoint_id)

    @property
    def available(self) -> bool:
        return super().available and self.endpoint is not None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        # Alert automations filter on these (e.g. no "gone quiet" alert for Occasional).
        return {"groups": self.endpoint.groups} if self.endpoint else None


class Action1HubEntity[_C: (Action1Coordinator, Action1KevCoordinator)](CoordinatorEntity[_C]):
    """An entity on the service device that stands for the Action1 organization."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: _C, key: str) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.org_id}_{key}"
        self._attr_translation_key = key
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.org_id)},
            name=coordinator.config_entry.title,
            manufacturer="Action1",
            entry_type=DeviceEntryType.SERVICE,
        )


def add_endpoint_entities(
    coordinator: Action1Coordinator,
    async_add_entities: AddConfigEntryEntitiesCallback,
    factory: Callable[[str], Iterable[Entity]],
) -> None:
    """Add entities for every PC now, and for PCs that appear in later polls."""
    known: set[str] = set()

    @callback
    def add_new() -> None:
        new = coordinator.data.keys() - known
        known.update(new)
        async_add_entities(entity for endpoint_id in new for entity in factory(endpoint_id))

    add_new()
    coordinator.config_entry.async_on_unload(coordinator.async_add_listener(add_new))
