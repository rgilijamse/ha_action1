# Action1 for Home Assistant

Patch state of the PCs that [Action1](https://www.action1.com/) manages, as Home
Assistant entities: missing updates, pending reboots, when each PC last checked in.
Read-only: the integration never deploys updates, reboots or runs anything.

Early development, tested against one Action1 organization in the North America
region (Windows 11 PCs and one Ubuntu server).

- [x] Per-PC update, vulnerability, reboot and last-seen sensors (hourly poll)
- [x] Ignored groups (e.g. PCs in storage), refresh button, last-successful-poll sensor
- [ ] "Critical missing since" / "reboot pending since", kept across restarts
- [ ] Known-exploited CVEs per PC (Action1's `cisa_kev` flag)

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
| `sensor.<pc>_critical_vulnerabilities` | Open critical CVEs (usually high: third-party software counts too) |
| `sensor.<pc>_last_seen` | Last check-in with Action1; `device_name`, `platform`, `os`, `agent_version` as attributes |
| `sensor.<pc>_days_since_seen` | Same, as a number for graphs and thresholds |
| `sensor.<pc>_last_boot` | Last boot (diagnostic) |
| `binary_sensor.<pc>_reboot_required` | On while updates wait for a restart |
| `binary_sensor.<pc>_connected` | Whether Action1 sees the agent online (diagnostic) |

Every per-PC entity has a `groups` attribute with its Action1 group names, so
automations can treat groups differently (e.g. no "gone quiet" alert for laptops
that are only used now and then).

On the organization's device:

| Entity | What it is |
|---|---|
| `sensor.action1_<org>_last_successful_poll` | When Action1 last answered. Stays available while polls fail, so an alert can tell how long they have been failing. |
| `button.action1_<org>_refresh_now` | Poll now instead of waiting for the hourly poll |

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

## Development

```
podman build -t localhost/ha-action1-test -f tools/Containerfile tools/
podman run --rm -v "$PWD":/src:ro localhost/ha-action1-test pytest
```

The probe dumps raw API responses to `tools/out/` (gitignored):

```
ACTION1_REGION=na ACTION1_CLIENT_ID=... ACTION1_CLIENT_SECRET=... tools/action1_probe.py [--kev]
```
