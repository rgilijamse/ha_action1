"""Polls Action1 for the patch state of every managed endpoint."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import logging
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .api import Action1AuthError, Action1Client, Action1Error, parse_time, to_int
from .const import CONF_IGNORED_GROUPS, CONF_ORG_ID, DOMAIN, SCAN_INTERVAL

if TYPE_CHECKING:
    from . import Action1ConfigEntry

_LOGGER = logging.getLogger(__name__)


def _counts(value: Any) -> tuple[int | None, int | None]:
    """Split Action1's {"critical": n, "other": n} objects."""
    if not isinstance(value, dict):
        return None, None
    return to_int(value.get("critical")), to_int(value.get("other"))


@dataclass
class Endpoint:
    """One managed PC as of the last poll."""

    id: str
    name: str
    device_name: str | None
    groups: list[str]
    platform: str | None
    os: str | None
    agent_version: str | None
    manufacturer: str | None
    serial: str | None
    connected: bool
    last_seen: datetime | None
    last_boot: datetime | None
    reboot_required: bool | None
    critical_updates: int | None
    other_updates: int | None
    critical_vulnerabilities: int | None

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> Endpoint:
        critical_updates, other_updates = _counts(raw.get("missing_updates"))
        critical_vulns, _ = _counts(raw.get("vulnerabilities"))
        reboot = raw.get("reboot_required")
        return cls(
            id=raw["id"],
            name=raw.get("name") or raw.get("device_name") or raw["id"],
            device_name=raw.get("device_name"),
            groups=[g["name"] for g in raw.get("group_membership") or [] if g.get("name")],
            platform=raw.get("platform"),
            os=raw.get("OS"),
            agent_version=raw.get("agent_version"),
            manufacturer=raw.get("manufacturer"),
            serial=raw.get("serial"),
            connected=raw.get("status") == "Connected",
            last_seen=parse_time(raw.get("last_seen")),
            last_boot=parse_time(raw.get("last_boot_time")),
            reboot_required={"Yes": True, "No": False}.get(reboot),
            critical_updates=critical_updates,
            other_updates=other_updates,
            critical_vulnerabilities=critical_vulns,
        )

    @property
    def days_since_seen(self) -> float | None:
        if not self.last_seen:
            return None
        return round((dt_util.utcnow() - self.last_seen).total_seconds() / 86400, 1)

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, self.id)},
            name=self.name,
            manufacturer=self.manufacturer,
            model=self.platform,
            serial_number=self.serial,
            sw_version=self.os,
        )


class Action1Coordinator(DataUpdateCoordinator[dict[str, Endpoint]]):
    """Fetches all endpoints in one paged call, minus the ignored groups."""

    config_entry: Action1ConfigEntry

    def __init__(
        self, hass: HomeAssistant, entry: Action1ConfigEntry, client: Action1Client
    ) -> None:
        super().__init__(
            hass, _LOGGER, config_entry=entry, name=DOMAIN, update_interval=SCAN_INTERVAL
        )
        self.client = client
        self.org_id: str = entry.data[CONF_ORG_ID]
        self.ignored_groups = set(entry.options.get(CONF_IGNORED_GROUPS, []))
        # Every group name seen, ignored ones included, for the options form.
        self.all_groups: set[str] = set()
        self.last_success: datetime | None = None

    async def _async_update_data(self) -> dict[str, Endpoint]:
        try:
            raw = await self.client.get_endpoints(self.org_id)
        except Action1AuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except Action1Error as err:
            raise UpdateFailed(str(err)) from err
        endpoints = [Endpoint.from_api(item) for item in raw if item.get("id")]
        self.all_groups = {g for ep in endpoints for g in ep.groups}
        self.last_success = dt_util.utcnow()
        return {
            ep.id: ep for ep in endpoints if not self.ignored_groups.intersection(ep.groups)
        }
