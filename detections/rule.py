#!/usr/bin/env python3
"""The SR-B2-8 detection rule: alert on a denial burst from one principal.

The product (both modes, T5) logs every authz denial as:

    2026/10/20 03:20:47 authz: deny sub=<uuid> target_org=<uuid> decision=not-a-member

This module is the detector side: given container log lines, find
principals whose denial count crosses a threshold. The shape of the rule
-- a count per principal, not per (principal, org) pair -- is deliberate:
one account probing MANY orgs is the cross-tenant scan the rule exists
to catch, and a per-pair threshold would let an attacker spread 4 probes
across every org in the platform and stay silent forever.

Pure function on lines -> alerts, no IO, so the unit tests (test_rule.py)
need no stack; replay.py supplies real log lines from the live product.

Threshold semantics: alert when a principal's total reaches the
threshold (>=, not >). DEFAULT_THRESHOLD=5 is a lab number -- a single
fat-fingered request is noise, a scan is not -- and is expected to be
tuned when M2+ adds real users.
"""

import re
from collections import Counter, defaultdict

DEFAULT_THRESHOLD = 5

# authz: deny sub=<uuid> target_org=<uuid> decision=<word>
DENY_RE = re.compile(
    r"authz: deny sub=(\S+) target_org=(\S+) decision=(\S+)"
)


def find_alerts(lines, threshold=DEFAULT_THRESHOLD):
    """Return one alert per principal whose denial count >= threshold.

    Each alert carries the evidence an operator needs to act without
    grepping: who (sub), how many (count), which orgs (target_orgs,
    sorted distinct), and one real line (sample).
    """
    counts = Counter()
    orgs = defaultdict(set)
    samples = {}

    for line in lines:
        m = DENY_RE.search(line)
        if not m:
            continue  # boot banners, WARN fallbacks, query errors -- not denials
        sub, org, _decision = m.groups()
        counts[sub] += 1
        orgs[sub].add(org)
        samples.setdefault(sub, line.rstrip())

    alerts = []
    for sub, count in counts.items():
        if count >= threshold:
            alerts.append({
                "rule": "deny-burst>=%d" % threshold,
                "sub": sub,
                "count": count,
                "target_orgs": sorted(orgs[sub]),
                "sample": samples[sub],
            })
    return alerts
