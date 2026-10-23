#!/usr/bin/env python3
"""Dump raw Action1 API responses to answer the plan's open questions.

  ACTION1_REGION=eu ACTION1_CLIENT_ID=... ACTION1_CLIENT_SECRET=... tools/action1_probe.py
  ... tools/action1_probe.py --org <org_id>      # pick an organization when there are several
  ... tools/action1_probe.py --try-requery       # also POST the installed-updates requery once

Read-only apart from --try-requery. Stdlib only, so it runs on the host without installs.
Writes every response to tools/out/ (gitignored: it holds hostnames, users and IPs) and
prints a summary. The secret is only read from the environment and is never written out.

API shape, from Action1's PSAction1 module: POST {base}/oauth2/token with a JSON body
{client_id, client_secret} returns {access_token, expires_in}; list calls page with
from/limit (max 200) and return {items, total_items, next_page}.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request

REGIONS = {
    "na": "https://app.action1.com/api/3.0",
    "na-2": "https://app.na-2.action1.com/api/3.0",
    "eu": "https://app.eu.action1.com/api/3.0",
    "au": "https://app.au.action1.com/api/3.0",
    "uk": "https://app.uk.action1.com/api/3.0",
}
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUT = Path(__file__).resolve().parent / "out"
PAGE = 200
MAX_CVE_DETAIL = 3


class Api:
    def __init__(self, base: str, client_id: str, secret: str) -> None:
        self.base = base
        token = self.request("POST", "/oauth2/token", {"client_id": client_id, "client_secret": secret}, auth=False)
        self.token = token["access_token"]
        # Keep the token's metadata (lifetime, type) but never the token itself.
        save("token_meta", {k: v for k, v in token.items() if "token" not in k})

    def request(self, method: str, path: str, body: dict | None = None, auth: bool = True):
        url = path if path.startswith("http") else self.base + path
        req = urllib.request.Request(url, method=method)
        req.add_header("Accept", "application/json")
        if auth:
            req.add_header("Authorization", f"Bearer {self.token}")
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            req.add_header("Content-Type", "application/json; charset=utf-8")
        try:
            with urllib.request.urlopen(req, data, timeout=60) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as err:
            detail = err.read().decode(errors="replace")[:500]
            raise SystemExit(f"{method} {path}: HTTP {err.code}\n{detail}") from None
        return json.loads(raw) if raw else None

    def paged(self, path: str, params: dict | None = None) -> dict:
        """Fetch every page; return the first page's envelope with all items merged in."""
        items, offset, first = [], 0, None
        while True:
            query = urllib.parse.urlencode({**(params or {}), "from": offset, "limit": PAGE})
            page = self.request("GET", f"{path}?{query}")
            first = first or page
            batch = page.get("items") or []
            items.extend(batch)
            offset += len(batch)
            # total_items comes back as a string ("3"), not a number.
            if not batch or offset >= int(page.get("total_items") or 0):
                break
        return {**first, "items": items}


def save(name: str, data) -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / f"{name}.json").write_text(json.dumps(data, indent=2, ensure_ascii=False))


def keys_of(items: list[dict]) -> list[str]:
    return sorted({k for item in items for k in item})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--org", help="organization id (default: the only one)")
    parser.add_argument("--try-requery", action="store_true", help="POST /updates/installed/{org}/requery once")
    args = parser.parse_args()

    region = os.environ.get("ACTION1_REGION", "eu")
    if region not in REGIONS:
        sys.exit(f"ACTION1_REGION must be one of {', '.join(REGIONS)}")
    try:
        client_id, secret = os.environ["ACTION1_CLIENT_ID"], os.environ["ACTION1_CLIENT_SECRET"]
    except KeyError as err:
        sys.exit(f"set {err.args[0]} in the environment")

    api = Api(REGIONS[region], client_id, secret)
    print(f"login ok ({region}); token lifetime: {json.loads((OUT / 'token_meta.json').read_text()).get('expires_in')} s")

    orgs = api.paged("/organizations")
    save("organizations", orgs)
    print(f"organizations: {[(o.get('id'), o.get('name')) for o in orgs['items']]}")
    org = args.org or (orgs["items"][0]["id"] if len(orgs["items"]) == 1 else None)
    if not org:
        sys.exit("several organizations: pass --org <id>")

    endpoints = api.paged(f"/endpoints/managed/{org}", {"fields": "*"})
    save("endpoints_managed", endpoints)
    eps = endpoints["items"]
    print(f"\nendpoints: {len(eps)} (envelope keys: {sorted(k for k in endpoints if k != 'items')})")
    print(f"endpoint fields: {keys_of(eps)}")
    for ep in eps:
        print("  " + json.dumps({k: ep.get(k) for k in (
            "id", "name", "last_seen", "missing_critical_updates", "missing_other_updates", "reboot_required", "OS",
        )}, ensure_ascii=False))
    reboot = api.paged(f"/endpoints/managed/{org}", {"reboot_required": "Yes"})
    save("endpoints_reboot_required", reboot)
    print(f"reboot_required=Yes filter: {[e.get('name') for e in reboot['items']]}")

    vulns = api.paged(f"/vulnerabilities/{org}")
    save("vulnerabilities", vulns)
    cves = vulns["items"]
    print(f"\nvulnerabilities: {len(cves)} (envelope keys: {sorted(k for k in vulns if k != 'items')})")
    print(f"vulnerability fields: {keys_of(cves)}")
    for cve in cves[:MAX_CVE_DETAIL]:
        cve_id = cve.get("cve_id")
        detail = api.paged(f"/vulnerabilities/{org}/{cve_id}/endpoints")
        save(f"vulnerability_endpoints_{cve_id}", detail)
        print(f"  {cve_id}: {len(detail['items'])} endpoint(s), fields {keys_of(detail['items'])}")

    try:
        with urllib.request.urlopen(KEV_URL, timeout=60) as resp:
            kev = {v["cveID"] for v in json.load(resp)["vulnerabilities"]}
        hits = sorted(c.get("cve_id") for c in cves if c.get("cve_id") in kev)
        print(f"\nCISA KEV: {len(kev)} CVEs listed; open in Action1 and on KEV: {hits or 'none'}")
    except (urllib.error.URLError, KeyError, ValueError) as err:
        print(f"\nCISA KEV fetch failed: {err}")

    if args.try_requery:
        try:
            api.request("POST", f"/updates/installed/{org}/requery")
            print("\nrequery: allowed with this key")
        except SystemExit as err:
            print(f"\nrequery: refused ({str(err).splitlines()[0]})")

    print(f"\nraw responses in {OUT}")


if __name__ == "__main__":
    main()
