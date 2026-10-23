"""Async client for the Action1 REST API (v3.0).

Deliberately free of Home Assistant imports so tools/ can use it from the CLI.
Paths, paging and token handling follow Action1's own PowerShell module
(github.com/Action1Corp/PSAction1); field formats were checked against a real tenant.
"""
from __future__ import annotations

from datetime import UTC, datetime
import time
from typing import Any

import aiohttp

REGIONS = {
    "na": "https://app.action1.com/api/3.0",
    "na-2": "https://app.na-2.action1.com/api/3.0",
    "eu": "https://app.eu.action1.com/api/3.0",
    "au": "https://app.au.action1.com/api/3.0",
    "uk": "https://app.uk.action1.com/api/3.0",
}
PAGE_LIMIT = 200
# Log in again this long before the token expires.
TOKEN_MARGIN = 60
TIMEOUT = aiohttp.ClientTimeout(total=60)


class Action1Error(Exception):
    """Unexpected API response or transport failure."""


class Action1AuthError(Action1Error):
    """The API credentials were rejected."""


def parse_time(value: str | None) -> datetime | None:
    """Parse Action1's '2026-10-23_09-48-30' (UTC) timestamps."""
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d_%H-%M-%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def to_int(value: Any) -> int | None:
    """Action1 sends many numbers as strings ("3")."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class Action1Client:
    """API session for one set of API credentials."""

    def __init__(
        self, session: aiohttp.ClientSession, region: str, client_id: str, client_secret: str
    ) -> None:
        self._session = session
        self.base = REGIONS[region]
        self._client_id = client_id
        self._client_secret = client_secret
        self._token: str | None = None
        self._expires = 0.0

    async def login(self) -> None:
        """Fetch a new access token."""
        body = {"client_id": self._client_id, "client_secret": self._client_secret}
        try:
            async with self._session.post(
                f"{self.base}/oauth2/token", json=body, timeout=TIMEOUT
            ) as resp:
                # A wrong ID or secret gets 400 or 401, with an explanation in the body.
                if resp.status in (400, 401):
                    raise Action1AuthError(await self._message(resp))
                if resp.status != 200:
                    raise Action1Error(f"login: HTTP {resp.status}: {await self._message(resp)}")
                data = await resp.json(content_type=None)
        except (aiohttp.ClientError, TimeoutError) as err:
            raise Action1Error(f"login: {err}") from err
        if not data.get("access_token"):
            raise Action1Error("login: no access_token in reply")
        self._token = data["access_token"]
        self._expires = time.monotonic() + (to_int(data.get("expires_in")) or 3600) - TOKEN_MARGIN

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET with the bearer token; logs in again once when it is rejected."""
        for attempt in (1, 2):
            if not self._token or time.monotonic() >= self._expires:
                await self.login()
            try:
                async with self._session.get(
                    f"{self.base}{path}",
                    params=params,
                    headers={"Authorization": f"Bearer {self._token}", "Accept": "application/json"},
                    timeout=TIMEOUT,
                ) as resp:
                    if resp.status == 401 and attempt == 1:
                        self._token = None
                        continue
                    if resp.status == 401:
                        raise Action1AuthError(await self._message(resp))
                    if resp.status != 200:
                        raise Action1Error(f"GET {path}: HTTP {resp.status}: {await self._message(resp)}")
                    return await resp.json(content_type=None)
            except (aiohttp.ClientError, TimeoutError) as err:
                raise Action1Error(f"GET {path}: {err}") from err
        raise Action1Error(f"GET {path}: token rejected twice")

    async def _paged(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Fetch every page of a list call (from/limit, total_items)."""
        items: list[dict[str, Any]] = []
        while True:
            page = await self._get(path, {**(params or {}), "from": len(items), "limit": PAGE_LIMIT})
            batch = page.get("items") or []
            items.extend(batch)
            if not batch or len(items) >= (to_int(page.get("total_items")) or 0):
                return items

    async def get_organizations(self) -> list[dict[str, Any]]:
        return await self._paged("/organizations")

    async def get_endpoints(self, org_id: str) -> list[dict[str, Any]]:
        """Return every managed endpoint with all fields (patch and reboot state included)."""
        return await self._paged(f"/endpoints/managed/{org_id}", {"fields": "*"})

    @staticmethod
    async def _message(resp: aiohttp.ClientResponse) -> str:
        try:
            data = await resp.json(content_type=None)
        except (ValueError, aiohttp.ClientError):
            return (await resp.text())[:200]
        if isinstance(data, dict):
            return str(data.get("user_message") or data.get("developer_message") or data)[:200]
        return str(data)[:200]
