"""Sensors for Action1."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import EntityCategory, UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import Action1ConfigEntry
from .coordinator import Endpoint
from .entity import Action1EndpointEntity, Action1HubEntity, add_endpoint_entities


@dataclass(frozen=True, kw_only=True)
class Action1SensorDescription(SensorEntityDescription):
    value_fn: Callable[[Endpoint], datetime | float | int | None]
    attrs_fn: Callable[[Endpoint], dict[str, Any]] | None = None


SENSORS: tuple[Action1SensorDescription, ...] = (
    Action1SensorDescription(
        key="critical_updates",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda e: e.critical_updates,
    ),
    Action1SensorDescription(
        key="other_updates",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda e: e.other_updates,
    ),
    Action1SensorDescription(
        key="critical_vulnerabilities",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda e: e.critical_vulnerabilities,
    ),
    Action1SensorDescription(
        key="last_seen",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda e: e.last_seen,
        attrs_fn=lambda e: {
            "device_name": e.device_name,
            "platform": e.platform,
            "os": e.os,
            "agent_version": e.agent_version,
        },
    ),
    Action1SensorDescription(
        key="days_since_seen",
        device_class=SensorDeviceClass.DURATION,
        native_unit_of_measurement=UnitOfTime.DAYS,
        suggested_display_precision=1,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda e: e.days_since_seen,
    ),
    Action1SensorDescription(
        key="last_boot",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda e: e.last_boot,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: Action1ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    async_add_entities([LastPollSensor(coordinator)])
    add_endpoint_entities(
        coordinator,
        async_add_entities,
        lambda endpoint_id: (
            Action1Sensor(coordinator, endpoint_id, description) for description in SENSORS
        ),
    )


class Action1Sensor(Action1EndpointEntity, SensorEntity):
    """A value from the PC's record in the last poll."""

    entity_description: Action1SensorDescription

    def __init__(self, coordinator, endpoint_id: str, description: Action1SensorDescription) -> None:
        super().__init__(coordinator, endpoint_id, description.key)
        self.entity_description = description

    @property
    def native_value(self) -> datetime | float | int | None:
        return self.entity_description.value_fn(self.endpoint)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        attrs = super().extra_state_attributes
        if attrs is not None and self.entity_description.attrs_fn:
            attrs |= self.entity_description.attrs_fn(self.endpoint)
        return attrs


class LastPollSensor(Action1HubEntity, SensorEntity):
    """When Action1 last answered; stays available while polls fail, so alerts can age it."""

    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator, "last_successful_poll")

    @property
    def available(self) -> bool:
        return self.coordinator.last_success is not None

    @property
    def native_value(self) -> datetime | None:
        return self.coordinator.last_success
