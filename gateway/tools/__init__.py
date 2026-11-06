"""Hardened tool implementations for the BrokenBazaar gateway.

These are the CORRECT implementations, written before the naive ones
(AGENTS.md house rule). The gateway service that mediates and hosts them
-- policy, audit pre-record, OPA -- lands in T5; this package is the
tools themselves, so they can be written and tested on their own terms.

Stdlib only. No pip, no pytest: the house rule exists because a
dependency is a trust decision, and nothing here needs one.

Layout:
    fetch.py      http_fetch -- the SR-B5-3 / SR-B7-1 implementation
    documents.py  read_document -- the D5b internal-route client
    test_tools.py stdlib unittest for both
"""
