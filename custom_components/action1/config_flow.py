"""Config flow for Action1."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlowWithReload,
)
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .api import REGIONS, Action1AuthError, Action1Client, Action1Error
from .const import CONF_IGNORED_GROUPS, CONF_ORG_ID, CONF_REGION, DOMAIN

SECRET_SELECTOR = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))
REGION_SELECTOR = SelectSelector(
    SelectSelectorConfig(
        options=list(REGIONS), translation_key=CONF_REGION, mode=SelectSelectorMode.DROPDOWN
    )
)


class Action1ConfigFlow(ConfigFlow, domain=DOMAIN):
    """Log in with an Action1 API credential and pick the organization."""

    VERSION = 1

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        self._orgs: dict[str, str] = {}

    @staticmethod
    def async_get_options_flow(config_entry: ConfigEntry) -> Action1OptionsFlow:
        return Action1OptionsFlow()

    async def _organizations(self, data: dict[str, Any]) -> dict[str, str]:
        """Log in and return {org_id: name}."""
        client = Action1Client(
            async_get_clientsession(self.hass),
            data[CONF_REGION],
            data[CONF_CLIENT_ID],
            data[CONF_CLIENT_SECRET],
        )
        orgs = await client.get_organizations()
        return {o["id"]: o.get("name") or o["id"] for o in orgs if o.get("id")}

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            data = {
                CONF_REGION: user_input[CONF_REGION],
                CONF_CLIENT_ID: user_input[CONF_CLIENT_ID].strip(),
                CONF_CLIENT_SECRET: user_input[CONF_CLIENT_SECRET].strip(),
            }
            try:
                orgs = await self._organizations(data)
            except Action1AuthError:
                errors["base"] = "invalid_auth"
            except Action1Error:
                errors["base"] = "cannot_connect"
            else:
                if not orgs:
                    return self.async_abort(reason="no_organizations")
                self._data, self._orgs = data, orgs
                if len(orgs) == 1:
                    return await self._create(next(iter(orgs)))
                return await self.async_step_organization()
        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(
                vol.Schema(
                    {
                        vol.Required(CONF_REGION): REGION_SELECTOR,
                        vol.Required(CONF_CLIENT_ID): str,
                        vol.Required(CONF_CLIENT_SECRET): SECRET_SELECTOR,
                    }
                ),
                user_input or {CONF_REGION: "na"},
            ),
            errors=errors,
        )

    async def async_step_organization(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return await self._create(user_input[CONF_ORG_ID])
        return self.async_show_form(
            step_id="organization",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_ORG_ID): SelectSelector(
                        SelectSelectorConfig(
                            options=[
                                SelectOptionDict(value=org_id, label=name)
                                for org_id, name in self._orgs.items()
                            ]
                        )
                    )
                }
            ),
        )

    async def _create(self, org_id: str) -> ConfigFlowResult:
        await self.async_set_unique_id(org_id)
        self._abort_if_unique_id_configured()
        return self.async_create_entry(
            title=f"Action1 {self._orgs[org_id]}",
            data={**self._data, CONF_ORG_ID: org_id},
            options={CONF_IGNORED_GROUPS: []},
        )

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            data = {
                CONF_REGION: entry.data[CONF_REGION],
                CONF_CLIENT_ID: user_input[CONF_CLIENT_ID].strip(),
                CONF_CLIENT_SECRET: user_input[CONF_CLIENT_SECRET].strip(),
            }
            try:
                orgs = await self._organizations(data)
            except Action1AuthError:
                errors["base"] = "invalid_auth"
            except Action1Error:
                errors["base"] = "cannot_connect"
            else:
                if entry.data[CONF_ORG_ID] not in orgs:
                    errors["base"] = "wrong_organization"
                else:
                    return self.async_update_reload_and_abort(entry, data_updates=data)
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=self.add_suggested_values_to_schema(
                vol.Schema(
                    {
                        vol.Required(CONF_CLIENT_ID): str,
                        vol.Required(CONF_CLIENT_SECRET): SECRET_SELECTOR,
                    }
                ),
                {CONF_CLIENT_ID: entry.data[CONF_CLIENT_ID]},
            ),
            description_placeholders={"title": entry.title},
            errors=errors,
        )


class Action1OptionsFlow(OptionsFlowWithReload):
    """Choose Action1 groups whose PCs get no entities (e.g. PCs in storage)."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(data=user_input)
        current = self.config_entry.options.get(CONF_IGNORED_GROUPS, [])
        coordinator = getattr(self.config_entry, "runtime_data", None)
        groups = sorted(set(current) | (coordinator.all_groups if coordinator else set()))
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(CONF_IGNORED_GROUPS, default=current): SelectSelector(
                        SelectSelectorConfig(
                            options=groups,
                            multiple=True,
                            custom_value=True,
                            mode=SelectSelectorMode.DROPDOWN,
                        )
                    )
                }
            ),
        )
