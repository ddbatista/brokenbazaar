# The BrokenBazaar gateway: Python service + the OPA policy binary.
#
# Two pinned artifacts, pinned DIFFERENTLY on purpose (AGENTS.md,
# "Pinning: strength follows what the artifact does"):
#
#   python:3.13-slim   by TAG+digest as a runtime base
#   openpolicyagent/opa by DIGEST, because it is a binary that makes
#                       security decisions at runtime and nothing
#                       downstream verifies it. Swap it and the gate's
#                       behaviour changes with no signal anywhere.
#
# The OPA image has no shell and no package manager, so it can only ever
# be a COPY source -- it cannot be a base. That is why this is a
# multi-stage copy rather than a second Compose service: `opa run
# --server` would reintroduce a network hop per policy evaluation, which
# is the coupling the jev-lab port exists to argue against (T0).
#
# ONE PIN SERVES CI AND PRODUCTION. `make test-policy` runs `opa test`
# from this same digest, so the binary that tests the policy is the
# binary that enforces it -- M1 T0's finding (a CI toolchain pin that
# GOTOOLCHAIN silently overrode) applied one layer up.

FROM openpolicyagent/opa@sha256:895872de1e8dc5b82e04f9410d2d1ada2f72d28fdcdba0e8789d91cfc27ec0d0 AS opa

FROM python:3.13-slim@sha256:b3575dcf816cdacc5292df77a6e3e59b8941631078373a045efa2ac1e9c5c3b2

COPY --from=opa /opa /usr/local/bin/opa

WORKDIR /gateway

# Stdlib only -- there is no requirements.txt and no pip install, by
# house rule. If this ever needs one, that is an entry in
# PROPOSED-DEPS.md, not a quiet layer here.
COPY . /gateway

# The policy is COPIED IN rather than mounted: the artifact that is
# reviewed is the artifact that runs. A bind-mounted policy would let the
# running gate diverge from the committed one with no signal -- which is
# the same argument the digest pin makes about the binary.
ENV POLICY_DIR=/gateway/policy \
    GATEWAY_AUDIT_PATH=/audit/gateway.jsonl \
    PORT=8081

# Non-root. The gateway reads policy and writes one append-only file; it
# has no reason to own either.
#
# /audit is 1777 -- world-writable WITH the sticky bit (T6 D1). The named
# `audit` volume is populated from this directory on first mount, so this
# mode is what the shared volume gets. Two writers, two uids: the gateway
# (10001) writes gateway.jsonl, the vulnerable agent (distroless nonroot,
# 65532) writes agent.jsonl. World-writable lets the agent create its
# file; sticky stops it deleting or renaming the gateway's; and
# gateway.jsonl is created 0644, so the agent cannot rewrite it either. A
# compromised agent can therefore not erase the record of what it asked
# the gate to do -- the property the rejected one-volume-same-uid shape
# would have given away.
RUN useradd --system --uid 10001 gateway \
    && mkdir -p /audit \
    && chown gateway:gateway /audit \
    && chmod 1777 /audit
USER gateway:gateway

EXPOSE 8081

# boot() runs the startup probes and refuses to start if the policy, the
# redaction schema, the OPA binary, the audit path or TOOLS_SECRET is
# missing. A gateway that starts without those would fail open at the
# first call; failing at boot makes that impossible (D5.5).
ENTRYPOINT ["python3", "gate.py"]
