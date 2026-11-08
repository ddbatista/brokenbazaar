"""HARDENED, parsed the same way the Go processes parse it (M2-N4).

Three processes in two languages read HARDENED (api, agent, gateway).
Two parsers with different tolerance make the processes disagree about
which mode they are in -- a split brain no request reveals. So the
grammar is strict and frozen in mode_vectors.json, which this module's
tests and app/mode's tests both read:

    "true"          -> True
    "false" / unset -> False   (the M0 default: the lab boots vulnerable)
    anything else   -> ValueError, and the gateway refuses to start
"""

from __future__ import annotations

import os

ENV = "HARDENED"


def parse(raw: str) -> bool:
    if raw == "true":
        return True
    if raw in ("false", ""):
        return False
    raise ValueError(
        f'{ENV}={raw!r} is not a mode: expected "true", "false" or unset '
        "-- refusing to guess (M2-N4)")


def from_env() -> bool:
    return parse(os.getenv(ENV, ""))
