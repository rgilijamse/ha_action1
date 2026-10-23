# Action1 for Home Assistant

Patch state of the PCs that [Action1](https://www.action1.com/) manages, as Home
Assistant entities: missing updates, pending reboots, when each PC last checked in.
Read-only: the integration never deploys updates, reboots or runs anything.

Early development, tested against one Action1 organization in the North America
region (Windows 11 PCs and one Ubuntu server).

- [x] Per-PC update, vulnerability, reboot and last-seen sensors (hourly poll)
- [x] Ignored groups (e.g. PCs in storage), refresh button, last-successful-poll sensor
- [x] "Critical missing since" / "reboot pending since", kept across restarts
- [x] Known-exploited CVEs per PC (Action1's `cisa_kev` flag), checked every 6 hours

## Setup

1. Create an API credential in the Action1 console. A read-only role is enough.
2. Copy `custom_components/action1` into Home Assistant's `custom_components`
   folder (HACS can't install from this private repository), restart, then add the
   **Action1** integration and enter the region, client ID and client secret.
3. Optional: under **Configure**, pick Action1 groups to ignore. PCs in those groups
   get no entities.

## What you get

Per PC (device name = the PC's name in Action1, which can differ from its hostname):

| Entity | What it is |
|---|---|
| `sensor.<pc>_critical_updates_missing` | Missing critical updates |
| `sensor.<pc>_other_updates_missing` | Other missing updates |
| `sensor.<pc>_critical_updates_missing_since` | When the critical count last went from 0 to above 0; unknown while it is 0 |
| `sensor.<pc>_reboot_pending_since` | When the reboot flag last came on; unknown while it is off |
| `sensor.<pc>_known_exploited_cves` | Open CVEs that CISA lists as exploited in the wild; `cves` and `software` (e.g. `Google Chrome 144.0.7559.133 → 156.0.8078.48`) as attributes |
| `sensor.<pc>_critical_vulnerabilities` | Open critical CVEs (usually high: third-party software counts too) |
| `sensor.<pc>_last_seen` | Last check-in with Action1; `device_name`, `platform`, `os`, `agent_version` as attributes |
| `sensor.<pc>_days_since_seen` | Same, as a number for graphs and thresholds |
| `sensor.<pc>_last_boot` | Last boot (diagnostic) |
| `binary_sensor.<pc>_reboot_required` | On while updates wait for a restart |
| `binary_sensor.<pc>_connected` | Whether Action1 sees the agent online (diagnostic) |

Action1 doesn't say when a condition started, so the two "since" sensors are the
integration's own record: set at the first poll that sees the condition, cleared at
the first poll that doesn't. They're stored in `.storage/action1.<entry id>`, so a
restart keeps them, and they stay available while polls fail. A condition that was
already there when the integration was added dates from that first poll. Alerts can
compare them with `now()` in a template trigger, which also fires after a restart if
the threshold passed while HA was down.

The known-exploited check reads Action1's whole CVE list (thousands of records, ~30
pages: the API ignores a `cisa_kev` filter) and then the PCs for each flagged CVE, so
it runs every 6 hours rather than hourly. Its last result is stored too; after a
restart it is reused if it is less than an hour old, otherwise the check runs again
in the background.

Every per-PC entity has a `groups` attribute with its Action1 group names, so
automations can treat groups differently (e.g. no "gone quiet" alert for laptops
that are only used now and then).

On the organization's device:

| Entity | What it is |
|---|---|
| `sensor.action1_<org>_last_successful_poll` | When Action1 last answered. Stays available while polls fail, so an alert can tell how long they have been failing. |
| `sensor.action1_<org>_last_known_exploited_check` | When the known-exploited check last completed; stays available while it fails |
| `button.action1_<org>_refresh_now` | Poll and check now instead of waiting |

Numeric sensors have `state_class: measurement`, so they keep long-term statistics
past the recorder's purge.

A PC that leaves Action1, or moves to an ignored group, goes unavailable; delete its
device from the device page.

## API notes

Action1's public docs only give an overview. Paths, paging and token handling follow
Action1's PowerShell module ([PSAction1](https://github.com/Action1Corp/PSAction1));
field formats were checked against a real tenant with `tools/action1_probe.py`:

- `POST /oauth2/token` with `{client_id, client_secret}` → bearer token, 3600 s.
- `GET /endpoints/managed/{org}?fields=*` → every PC; counts are in
  `missing_updates` and `vulnerabilities` (`{critical, other}`); the flat
  `missing_critical_updates`/`missing_other_updates` fields are empty.
- Timestamps look like `2026-10-23_09-48-30` and are UTC. Totals come as strings.
- `update_status`/`vulnerability_status` show `ERROR` on healthy PCs too; not used.
- `GET /vulnerabilities/{org}` → one record per CVE with `cisa_kev` `Yes`/`No`;
  `GET /vulnerabilities/{org}/{cve}/endpoints` → the PCs, by `endpoint_id`, with the
  vulnerable software and available updates. `endpoint_name` there is the hostname,
  not the display name, so match on the ID.

## Development

```
podman build -t localhost/ha-action1-test -f tools/Containerfile tools/
podman run --rm -v "$PWD":/src:ro localhost/ha-action1-test pytest
```

The probe dumps raw API responses to `tools/out/` (gitignored):

```
ACTION1_REGION=na ACTION1_CLIENT_ID=... ACTION1_CLIENT_SECRET=... tools/action1_probe.py [--kev]
```
