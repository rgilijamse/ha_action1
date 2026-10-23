"""Constants for the Action1 integration."""
from datetime import timedelta

DOMAIN = "action1"

CONF_REGION = "region"
CONF_ORG_ID = "org_id"
CONF_IGNORED_GROUPS = "ignored_groups"

SCAN_INTERVAL = timedelta(hours=1)
# The known-exploited check reads every open CVE (thousands, ~30 pages) plus one call
# per flagged CVE, so it runs less often.
KEV_SCAN_INTERVAL = timedelta(hours=6)
# At startup, a stored result younger than this is used without checking again.
KEV_REUSE_AFTER_RESTART = timedelta(hours=1)
