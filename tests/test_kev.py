"""Known-exploited CVE check tests."""
from __future__ import annotations

from datetime import timedelta

from freezegun.api import FrozenDateTimeFactory
from homeassistant.core import HomeAssistant
import pytest
from pytest_homeassistant_custom_component.common import async_fire_time_changed

from custom_components.action1.const import DOMAIN

from .conftest import ORG_ID, PC_ACTIVE, PC_OCCASIONAL, SERVER, VULNS_URL
from .test_init import NOW, entity_ids, setup

KEV_KEY = "known_exploited_cves"


@pytest.fixture(autouse=True)
def frozen(freezer: FrozenDateTimeFactory) -> FrozenDateTimeFactory:
    freezer.move_to(NOW)
    return freezer


def state(hass: HomeAssistant, entry, key: str):
    return hass.states.get(entity_ids(hass, entry)[key])


def store_key(entry) -> str:
    return f"{DOMAIN}.{entry.entry_id}.kev"


async def test_known_exploited(hass, entry, api, hass_storage) -> None:
    await setup(hass, entry)

    active = state(hass, entry, f"{PC_ACTIVE}_{KEV_KEY}")
    assert active.state == "2"
    assert active.attributes["cves"] == ["CVE-2026-2441", "CVE-2026-5281"]
    assert active.attributes["software"] == [
        "Google Chrome 144.0.7559.133 → 156.0.8078.48",
        "Microsoft Edge 144.0.3719.115 → 156.0.4314.42",
    ]
    assert active.attributes["groups"] == ["Active"]
    # Open CVEs that aren't on the list don't count.
    occasional = state(hass, entry, f"{PC_OCCASIONAL}_{KEV_KEY}")
    assert occasional.state == "0"
    assert occasional.attributes["cves"] == []
    assert state(hass, entry, f"{SERVER}_{KEV_KEY}").state == "0"
    assert state(hass, entry, f"{ORG_ID}_last_known_exploited_check").state == NOW

    # One list read plus one call per flagged CVE; the unflagged one isn't fetched.
    assert api.calls(VULNS_URL) == 1
    assert api.calls(f"{VULNS_URL}/CVE-2026-5281/endpoints") == 1
    assert api.calls(f"{VULNS_URL}/CVE-2007-0842/endpoints") == 0
    assert hass_storage[store_key(entry)]["data"]["checked"] == NOW


async def test_runs_every_six_hours(hass, entry, api, frozen) -> None:
    await setup(hass, entry)
    for hours in range(1, 7):
        frozen.tick(timedelta(hours=1, seconds=1))
        async_fire_time_changed(hass)
        await hass.async_block_till_done()
        assert api.calls(VULNS_URL) == (2 if hours == 6 else 1), hours


async def test_recent_result_reused_after_restart(hass, entry, api, hass_storage) -> None:
    hass_storage[store_key(entry)] = {
        "version": 1,
        "key": store_key(entry),
        "data": {
            "checked": "2026-10-23T11:30:00+00:00",
            "endpoints": {SERVER: {"cves": ["CVE-2026-0001"], "software": ["OpenSSL 3.0.13"]}},
        },
    }
    await setup(hass, entry)
    assert api.calls(VULNS_URL) == 0
    assert state(hass, entry, f"{SERVER}_{KEV_KEY}").state == "1"
    assert state(hass, entry, f"{PC_ACTIVE}_{KEV_KEY}").state == "0"
    assert (
        state(hass, entry, f"{ORG_ID}_last_known_exploited_check").state
        == "2026-10-23T11:30:00+00:00"
    )


async def test_old_result_checked_again_after_restart(hass, entry, api, hass_storage) -> None:
    hass_storage[store_key(entry)] = {
        "version": 1,
        "key": store_key(entry),
        "data": {"checked": "2026-10-23T08:00:00+00:00", "endpoints": {}},
    }
    await setup(hass, entry)
    assert api.calls(VULNS_URL) == 1
    assert state(hass, entry, f"{PC_ACTIVE}_{KEV_KEY}").state == "2"


async def test_failed_check(hass, entry, api, frozen) -> None:
    await setup(hass, entry)
    api.kev_status = 500
    api.install()
    frozen.tick(timedelta(hours=6, seconds=1))
    async_fire_time_changed(hass)
    await hass.async_block_till_done()

    assert state(hass, entry, f"{PC_ACTIVE}_{KEV_KEY}").state == "unavailable"
    # The hourly poll still worked, and the last good check stays visible.
    assert state(hass, entry, f"{PC_ACTIVE}_critical_updates").state == "1"
    assert state(hass, entry, f"{ORG_ID}_last_known_exploited_check").state == NOW


async def test_first_check_fails(hass, entry, api) -> None:
    api.kev_status = 500
    api.install()
    await setup(hass, entry)
    assert state(hass, entry, f"{PC_ACTIVE}_{KEV_KEY}").state == "unavailable"
    assert state(hass, entry, f"{ORG_ID}_last_known_exploited_check").state == "unavailable"
    assert state(hass, entry, f"{PC_ACTIVE}_critical_updates").state == "1"


async def test_refresh_button_checks_too(hass, entry, api) -> None:
    await setup(hass, entry)
    await hass.services.async_call(
        "button", "press", {"entity_id": entity_ids(hass, entry)[f"{ORG_ID}_refresh"]}, blocking=True
    )
    await hass.async_block_till_done()
    assert api.calls(VULNS_URL) == 2
