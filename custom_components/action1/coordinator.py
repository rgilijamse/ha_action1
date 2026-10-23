"""Polls Action1 for the patch state of every managed endpoint."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
import logging
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .api import Action1AuthError, Action1Client, Action1Error, parse_time, to_int
from .const import (
    CONF_IGNORED_GROUPS,
    CONF_ORG_ID,
    DOMAIN,
    KEV_REUSE_AFTER_RESTART,
    KEV_SCAN_INTERVAL,
    SCAN_INTERVAL,
)

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
    # Tracked by the coordinator, not sent by Action1.
    critical_missing_since: datetime | None = None
    reboot_pending_since: datetime | None = None

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


STORAGE_VERSION = 1

# Conditions whose start the coordinator records: stored key -> test on a fresh poll.
# None means Action1 didn't say, which leaves the stored value as it is.
SINCE: dict[str, Callable[[Endpoint], bool | None]] = {
    "critical_missing_since": lambda e: (
        None if e.critical_updates is None else e.critical_updates > 0
    ),
    "reboot_pending_since": lambda e: e.reboot_required,
}


class Action1Coordinator(DataUpdateCoordinator[dict[str, Endpoint]]):
    """Fetches all endpoints in one paged call, minus the ignored groups."""

    config_entry: Action1ConfigEntry
    kev: Action1KevCoordinator

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
        # {endpoint_id: {key in SINCE: ISO timestamp}}, kept across restarts.
        self.store: Store[dict[str, dict[str, str]]] = Store(
            hass, STORAGE_VERSION, f"{DOMAIN}.{entry.entry_id}"
        )
        self.since: dict[str, dict[str, str]] = {}

    async def _async_setup(self) -> None:
        self.since = await self.store.async_load() or {}

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
        data = {
            ep.id: ep for ep in endpoints if not self.ignored_groups.intersection(ep.groups)
        }
        await self._track_since(data)
        return data

    async def _track_since(self, data: dict[str, Endpoint]) -> None:
        """Record when each condition started, clear it when it ends, and save changes."""
        now = dt_util.utcnow().replace(microsecond=0).isoformat()
        since: dict[str, dict[str, str]] = {}
        for ep in data.values():
            old = self.since.get(ep.id, {})
            new: dict[str, str] = {}
            for key, active in SINCE.items():
                state = active(ep)
                if state is None and key in old:
                    new[key] = old[key]
                elif state:
                    new[key] = old.get(key, now)
                if key in new:
                    setattr(ep, key, dt_util.parse_datetime(new[key]))
            if new:
                since[ep.id] = new
        if since != self.since:
            # PCs that left Action1 or the watched groups are dropped too.
            self.since = since
            await self.store.async_save(since)


def _software(item: dict[str, Any]) -> list[str]:
    """'Google Chrome 144.0.7559.133 → 156.0.8078.48' for each vulnerable product."""
    found = []
    for sw in item.get("software") or []:
        versions = ", ".join(v["version"] for v in sw.get("versions") or [] if v.get("version"))
        text = " ".join(filter(None, (sw.get("product_name"), versions)))
        updates = [u["version"] for u in sw.get("available_updates") or [] if u.get("version")]
        if updates:
            text += f" → {updates[-1]}"
        found.append(text)
    return found


class Action1KevCoordinator(DataUpdateCoordinator[dict[str, dict[str, list[str]]]]):
    """Finds the PCs with CVEs that Action1 flags as on CISA's known-exploited list.

    Data is {endpoint_id: {"cves": [...], "software": [...]}}, for every PC including
    those in ignored groups; PCs without such CVEs are absent. The last result is
    stored, so a restart doesn't repeat the ~60 calls a check takes.
    """

    config_entry: Action1ConfigEntry

    def __init__(
        self, hass: HomeAssistant, entry: Action1ConfigEntry, client: Action1Client
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"{DOMAIN} known-exploited CVEs",
            update_interval=KEV_SCAN_INTERVAL,
        )
        self.client = client
        self.org_id: str = entry.data[CONF_ORG_ID]
        self.store: Store[dict[str, Any]] = Store(
            hass, STORAGE_VERSION, f"{DOMAIN}.{entry.entry_id}.kev"
        )
        self.last_success: datetime | None = None

    async def async_restore(self) -> bool:
        """Load the stored result; True if it is recent enough to skip checking now."""
        stored = await self.store.async_load()
        if not stored:
            return False
        self.last_success = dt_util.parse_datetime(stored["checked"])
        self.async_set_updated_data(stored["endpoints"])
        return dt_util.utcnow() - self.last_success < KEV_REUSE_AFTER_RESTART

    async def _async_update_data(self) -> dict[str, dict[str, list[str]]]:
        found: dict[str, dict[str, list[str]]] = {}
        try:
            vulns = await self.client.get_vulnerabilities(self.org_id)
            # The API ignores a cisa_kev filter, so the whole list is read and filtered here.
            kev = sorted(v["cve_id"] for v in vulns if v.get("cisa_kev") == "Yes" and v.get("cve_id"))
            for cve_id in kev:
                for item in await self.client.get_vulnerability_endpoints(self.org_id, cve_id):
                    if not (endpoint_id := item.get("endpoint_id")):
                        continue
                    pc = found.setdefault(endpoint_id, {"cves": [], "software": []})
                    pc["cves"].append(cve_id)
                    pc["software"] = sorted(set(pc["software"]) | set(_software(item)))
        except Action1AuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except Action1Error as err:
            raise UpdateFailed(str(err)) from err
        self.last_success = dt_util.utcnow().replace(microsecond=0)
        await self.store.async_save({"checked": self.last_success.isoformat(), "endpoints": found})
        return found
