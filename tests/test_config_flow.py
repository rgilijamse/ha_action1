"""Config flow tests."""
from __future__ import annotations

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResultType

from custom_components.action1.const import DOMAIN

from .conftest import ORG_ID

USER_INPUT = {"region": "na", "client_id": " api-key-test ", "client_secret": "secret"}


async def start(hass):
    return await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )


async def test_single_organization(hass, api) -> None:
    result = await start(hass)
    assert result["type"] is FlowResultType.FORM
    result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "Action1 Alles"
    assert result["data"] == {
        "region": "na",
        "client_id": "api-key-test",
        "client_secret": "secret",
        "org_id": ORG_ID,
    }
    assert result["options"] == {"ignored_groups": []}
    assert result["result"].unique_id == ORG_ID


async def test_pick_organization(hass, api) -> None:
    api.orgs.append({"id": "org-2", "name": "Werk"})
    api.install()
    result = await start(hass)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["step_id"] == "organization"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"org_id": "org-2"})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "Action1 Werk"


async def test_invalid_auth(hass, api) -> None:
    api.token_status = 400
    api.install()
    result = await start(hass)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["errors"] == {"base": "invalid_auth"}


async def test_cannot_connect(hass, api) -> None:
    api.token_status = 503
    api.install()
    result = await start(hass)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["errors"] == {"base": "cannot_connect"}


async def test_already_configured(hass, api, entry) -> None:
    entry.add_to_hass(hass)
    result = await start(hass)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_INPUT)
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_reauth(hass, api, entry) -> None:
    entry.add_to_hass(hass)
    result = await entry.start_reauth_flow(hass)
    assert result["step_id"] == "reauth_confirm"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"client_id": "api-key-new", "client_secret": "new-secret"}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data["client_id"] == "api-key-new"
    assert entry.data["client_secret"] == "new-secret"


async def test_reauth_wrong_organization(hass, api, entry) -> None:
    api.orgs = [{"id": "org-2", "name": "Werk"}]
    api.install()
    entry.add_to_hass(hass)
    result = await entry.start_reauth_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"client_id": "api-key-new", "client_secret": "new-secret"}
    )
    assert result["errors"] == {"base": "wrong_organization"}
