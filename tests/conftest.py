"""Fixtures: a fake Action1 API on top of aioclient_mock.

Field names and formats are copied from a real tenant (tools/action1_probe.py);
names, IDs and counts are made up.
"""
from __future__ import annotations

import copy

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
from pytest_homeassistant_custom_component.test_util.aiohttp import AiohttpClientMocker

from custom_components.action1.api import REGIONS
from custom_components.action1.const import DOMAIN

BASE = REGIONS["na"]
ORG_ID = "00000000-0000-0000-0000-000000000001"
TOKEN_URL = f"{BASE}/oauth2/token"
ORGS_URL = f"{BASE}/organizations"
ENDPOINTS_URL = f"{BASE}/endpoints/managed/{ORG_ID}"
VULNS_URL = f"{BASE}/vulnerabilities/{ORG_ID}"

PC_ACTIVE = "10000000-0000-0000-0000-000000000001"
PC_OCCASIONAL = "20000000-0000-0000-0000-000000000002"
PC_STORED = "30000000-0000-0000-0000-000000000003"
SERVER = "40000000-0000-0000-0000-000000000004"


def make_endpoint(
    endpoint_id: str,
    name: str,
    group: str,
    *,
    last_seen: str = "2026-10-23_09-25-43",
    status: str = "Connected",
    platform: str = "Windows",
    reboot: str = "No",
    critical: int = 0,
    other: int = 0,
) -> dict:
    return {
        "id": endpoint_id,
        "type": "Endpoint",
        "self": f"{ENDPOINTS_URL}/{endpoint_id}/general",
        "organization_id": ORG_ID,
        "name": name,
        "device_name": name.split(" ")[0].upper(),
        "status": status,
        "last_seen": last_seen,
        "last_boot_time": "2026-10-18_11-44-13",
        "platform": platform,
        "OS": "Windows 11 (25H2)" if platform == "Windows" else "Ubuntu 24.04.5 LTS (Noble Numbat)",
        "agent_version": "6.0.664.1",
        "manufacturer": "LENOVO",
        "serial": "SN-" + endpoint_id[:8],
        "user": "TEST\\user",
        "reboot_required": reboot,
        "missing_updates": {"critical": critical, "other": other},
        "vulnerabilities": {"critical": 29, "other": 324},
        "update_status": "ERROR",
        "vulnerability_status": "ERROR",
        "online_status": "SUCCESS",
        "group_membership": [{"id": f"{group}_1700000000000", "name": group}],
        "missing_critical_updates": None,
        "missing_other_updates": None,
    }


def make_software(product: str, version: str, update: str | None) -> dict:
    return {
        "product_name": product,
        "platform": "Windows",
        "versions": [{"version": version, "uninstall_type": "auto", "install_type": ["MSI"]}],
        "available_updates": [
            {"version": update, "package_id": f"{product}_builtin", "version_id": f"{update}_1"}
        ] if update else [],
        "cve_origin": [{"source": "NVD"}],
    }


CHROME = make_software("Google Chrome", "144.0.7559.133", "156.0.8078.48")
EDGE = make_software("Microsoft Edge", "144.0.3719.115", "156.0.4314.42")
VCREDIST = make_software("Microsoft Visual C++ 2005 Redistributable", "8.0.56336", None)


def make_vulnerability(cve_id: str, kev: bool, software: list[dict]) -> dict:
    return {
        "cve_id": cve_id,
        "cvss_score": "8.8",
        "endpoints_count": "1",
        "published_date": "2026-03-01_10-00-00",
        "remediation_status": "Overdue",
        "software": software,
        "cisa_kev": "Yes" if kev else "No",
        "organization_id": ORG_ID,
    }


def make_vulnerable_endpoint(endpoint_id: str, software: list[dict]) -> dict:
    return {
        "endpoint_id": endpoint_id,
        "endpoint_name": "PC",
        "OS": "Microsoft Windows 11 Home",
        "software": software,
        "organization_id": ORG_ID,
        "user": "TEST\\user",
    }


class FakeAction1:
    """Registers Action1 endpoints on aioclient_mock; tweak fields, then call install()."""

    def __init__(self, mock: AiohttpClientMocker) -> None:
        self.mock = mock
        self.token_status = 200
        self.endpoints_status = 200
        self.orgs = [{"id": ORG_ID, "name": "Test Org", "type": "Organization"}]
        self.endpoints = [
            make_endpoint(PC_ACTIVE, "LT-Test", "Active", reboot="Yes", critical=1, other=2),
            make_endpoint(
                PC_OCCASIONAL, "Oude laptop", "Occasional",
                last_seen="2026-07-28_23-25-01", status="Disconnected", critical=4, other=14,
            ),
            make_endpoint(PC_STORED, "LT-Test (oud)", "Stored", last_seen="2026-02-10_13-47-43"),
            make_endpoint(SERVER, "server01", "Linux", platform="Linux", other=3),
        ]
        self.kev_status = 200
        self.vulnerabilities = [
            make_vulnerability("CVE-2026-5281", True, [CHROME, EDGE]),
            make_vulnerability("CVE-2026-2441", True, [CHROME]),
            make_vulnerability("CVE-2007-0842", False, [VCREDIST]),
        ]
        # {cve_id: endpoints}; the old PC in storage shares a CVE with the active one.
        self.vulnerable = {
            "CVE-2026-5281": [
                make_vulnerable_endpoint(PC_ACTIVE, [CHROME, EDGE]),
                make_vulnerable_endpoint(PC_STORED, [CHROME, EDGE]),
            ],
            "CVE-2026-2441": [make_vulnerable_endpoint(PC_ACTIVE, [CHROME])],
            "CVE-2007-0842": [make_vulnerable_endpoint(PC_OCCASIONAL, [VCREDIST])],
        }
        self.install()

    def install(self) -> None:
        self.mock.clear_requests()
        if self.token_status == 200:
            self.mock.post(TOKEN_URL, json={
                "access_token": "tok-1", "token_type": "Bearer", "expires_in": 3600,
            })
        else:
            self.mock.post(TOKEN_URL, status=self.token_status, json={
                "status": self.token_status, "type": "Error",
                "user_message": "To authenticate, provide API credentials (client ID and client secret).",
            })
        self.mock.get(ORGS_URL, json=self.page(self.orgs))
        self.mock.get(ENDPOINTS_URL, status=self.endpoints_status, json=self.page(self.endpoints))
        for cve_id, endpoints in self.vulnerable.items():
            self.mock.get(f"{VULNS_URL}/{cve_id}/endpoints", json=self.page(endpoints))
        self.mock.get(VULNS_URL, status=self.kev_status, json=self.page(self.vulnerabilities))

    @staticmethod
    def page(items: list[dict]) -> dict:
        # Totals and limits come back as strings.
        return {"items": copy.deepcopy(items), "total_items": str(len(items)), "limit": "200"}

    def calls(self, url: str) -> int:
        return sum(1 for call in self.mock.mock_calls if str(call[1]).split("?")[0] == url)


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    yield


@pytest.fixture
def api(aioclient_mock: AiohttpClientMocker) -> FakeAction1:
    return FakeAction1(aioclient_mock)


@pytest.fixture
def entry() -> MockConfigEntry:
    return MockConfigEntry(
        domain=DOMAIN,
        title="Action1 Test Org",
        unique_id=ORG_ID,
        data={
            "region": "na",
            "client_id": "api-key-test",
            "client_secret": "secret",
            "org_id": ORG_ID,
        },
        options={"ignored_groups": ["Stored"]},
    )
