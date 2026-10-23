"""Setup, polling and entity tests."""
from __future__ import annotations

from datetime import timedelta

from freezegun.api import FrozenDateTimeFactory
from homeassistant.config_entries import SOURCE_REAUTH, ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.setup import async_setup_component
import pytest
from pytest_homeassistant_custom_component.common import async_fire_time_changed

from custom_components.action1.api import parse_time
from custom_components.action1.const import DOMAIN

from .conftest import (
    ENDPOINTS_URL,
    ORG_ID,
    PC_ACTIVE,
    PC_OCCASIONAL,
    PC_STORED,
    SERVER,
    TOKEN_URL,
    make_endpoint,
)

NOW = "2026-10-23T12:00:00+00:00"


@pytest.fixture(autouse=True)
def frozen(freezer: FrozenDateTimeFactory) -> FrozenDateTimeFactory:
    freezer.move_to(NOW)
    return freezer


async def setup(hass: HomeAssistant, entry) -> None:
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()


def entity_ids(hass: HomeAssistant, entry) -> dict[str, str]:
    ent_reg = er.async_get(hass)
    return {e.unique_id: e.entity_id for e in er.async_entries_for_config_entry(ent_reg, entry.entry_id)}


async def poll(hass: HomeAssistant, frozen: FrozenDateTimeFactory) -> None:
    frozen.tick(timedelta(hours=1, seconds=1))
    async_fire_time_changed(hass)
    await hass.async_block_till_done()


def test_parse_time() -> None:
    assert parse_time("2026-10-23_09-48-30").isoformat() == "2026-10-23T09:48:30+00:00"
    assert parse_time("") is None
    assert parse_time("garbage") is None


async def test_entities(hass, entry, api) -> None:
    await setup(hass, entry)
    assert entry.state is ConfigEntryState.LOADED
    ids = entity_ids(hass, entry)

    assert hass.states.get(ids[f"{PC_ACTIVE}_critical_updates"]).state == "1"
    assert hass.states.get(ids[f"{PC_ACTIVE}_other_updates"]).state == "2"
    assert hass.states.get(ids[f"{PC_ACTIVE}_critical_vulnerabilities"]).state == "29"
    assert hass.states.get(ids[f"{PC_ACTIVE}_reboot_required"]).state == "on"
    assert hass.states.get(ids[f"{PC_ACTIVE}_connected"]).state == "on"
    assert hass.states.get(ids[f"{PC_OCCASIONAL}_connected"]).state == "off"
    assert hass.states.get(ids[f"{SERVER}_reboot_required"]).state == "off"

    last_seen = hass.states.get(ids[f"{PC_ACTIVE}_last_seen"])
    assert last_seen.state == "2026-10-23T09:25:43+00:00"
    assert last_seen.attributes["groups"] == ["Active"]
    assert last_seen.attributes["os"] == "Windows 11 (25H2)"
    assert hass.states.get(ids[f"{PC_ACTIVE}_days_since_seen"]).state == "0.1"
    assert hass.states.get(ids[f"{PC_OCCASIONAL}_days_since_seen"]).state == "86.5"
    assert hass.states.get(ids[f"{PC_OCCASIONAL}_critical_updates"]).attributes["groups"] == ["Occasional"]

    assert hass.states.get(ids[f"{ORG_ID}_last_successful_poll"]).state == NOW
    assert f"{ORG_ID}_refresh" in ids

    # The ignored group gets no entities and no device.
    assert not any(uid.startswith(PC_STORED) for uid in ids)
    dev_reg = dr.async_get(hass)
    assert dev_reg.async_get_device_by_identifier((DOMAIN, PC_STORED), entry.entry_id) is None
    device = dev_reg.async_get_device_by_identifier((DOMAIN, PC_ACTIVE), entry.entry_id)
    assert device.name == "LT-Test"
    assert device.sw_version == "Windows 11 (25H2)"


async def test_token_lifetime(hass, entry, api, frozen) -> None:
    await setup(hass, entry)
    coordinator = entry.runtime_data

    # Within its lifetime the token is reused.
    frozen.tick(timedelta(minutes=30))
    await coordinator.async_refresh()
    assert api.calls(TOKEN_URL) == 1
    assert api.calls(ENDPOINTS_URL) == 2

    # Tokens last 3600 s, as long as the poll interval: the hourly poll logs in again.
    await poll(hass, frozen)
    assert api.calls(TOKEN_URL) == 2
    assert api.calls(ENDPOINTS_URL) == 3


async def test_rejected_token_logs_in_again(hass, entry, api) -> None:
    await setup(hass, entry)
    api.mock.clear_requests()
    api.mock.post(TOKEN_URL, json={"access_token": "tok-2", "expires_in": "3600"})
    api.mock.get(ENDPOINTS_URL, status=401, json={"status": 401})
    await entry.runtime_data.async_refresh()
    # One new login, one retry; the retry is rejected too, so the credentials are bad.
    assert api.calls(TOKEN_URL) == 1
    assert api.calls(ENDPOINTS_URL) == 2
    flows = hass.config_entries.flow.async_progress()
    assert [f["context"]["source"] for f in flows] == [SOURCE_REAUTH]


async def test_rejected_credentials_start_reauth(hass, entry, api, frozen) -> None:
    await setup(hass, entry)
    api.token_status = 400
    api.endpoints_status = 401
    api.install()
    await poll(hass, frozen)
    flows = hass.config_entries.flow.async_progress()
    assert [f["context"]["source"] for f in flows] == [SOURCE_REAUTH]


async def test_failed_poll(hass, entry, api, frozen) -> None:
    await setup(hass, entry)
    ids = entity_ids(hass, entry)
    api.endpoints_status = 500
    api.install()
    await poll(hass, frozen)

    assert hass.states.get(ids[f"{PC_ACTIVE}_critical_updates"]).state == "unavailable"
    # Still shows the last good poll, so an alert can tell how long polls have failed.
    assert hass.states.get(ids[f"{ORG_ID}_last_successful_poll"]).state == NOW
    assert hass.states.get(ids[f"{ORG_ID}_refresh"]).state != "unavailable"


async def test_new_and_removed_pcs(hass, entry, api, frozen) -> None:
    await setup(hass, entry)
    new_pc = "f00dbabe-0000-0000-0000-000000000005"
    api.endpoints = [e for e in api.endpoints if e["id"] != PC_OCCASIONAL]
    api.endpoints.append(make_endpoint(new_pc, "Nieuwe PC", "Active"))
    api.install()
    await poll(hass, frozen)

    ids = entity_ids(hass, entry)
    assert hass.states.get(ids[f"{new_pc}_critical_updates"]).state == "0"
    assert hass.states.get(ids[f"{PC_OCCASIONAL}_critical_updates"]).state == "unavailable"

    # Gone PCs can be deleted from the device page; current ones and the hub can't.
    assert await async_setup_component(hass, "config", {})
    dev_reg = dr.async_get(hass)
    from custom_components.action1 import async_remove_config_entry_device

    for key, removable in ((PC_OCCASIONAL, True), (PC_ACTIVE, False), (ORG_ID, False)):
        device = dev_reg.async_get_device_by_identifier((DOMAIN, key), entry.entry_id)
        assert await async_remove_config_entry_device(hass, entry, device) is removable


async def test_refresh_button(hass, entry, api) -> None:
    await setup(hass, entry)
    ids = entity_ids(hass, entry)
    await hass.services.async_call(
        "button", "press", {"entity_id": ids[f"{ORG_ID}_refresh"]}, blocking=True
    )
    await hass.async_block_till_done()
    assert api.calls(ENDPOINTS_URL) == 2


async def test_options_list_groups(hass, entry, api) -> None:
    await setup(hass, entry)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    schema = result["data_schema"].schema
    selector = next(v for k, v in schema.items() if k == "ignored_groups")
    assert selector.config["options"] == ["Active", "Linux", "Occasional", "Stored"]

    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"ignored_groups": ["Stored", "Occasional"]}
    )
    await hass.async_block_till_done()
    assert entry.options == {"ignored_groups": ["Stored", "Occasional"]}
    assert PC_OCCASIONAL not in entry.runtime_data.data
