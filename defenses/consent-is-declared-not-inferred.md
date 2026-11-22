# Consent is declared, not inferred

*The control behind finding 07's hardened half: the consent channel. Boundary B6, leaf 1.2's data half, closing on M2's `tenant_data_egress`.*

## What it is

An installed tool's pin declares what it may **receive** — a vocabulary, `user_text` / `document_content`, chosen by the publisher at listing time and approved by the org at install time. Every installed-tool call is judged against that declaration: bytes the user did not type (`provenance.derived_from` outside `{"user"}`) to a tool that never declared them is denied as `tenant_data_egress` — the same reason string M2 wrote for egress, deliberately reused: **one requirement — tenant-derived bytes leaving without consent — two paths, one reason.** The same tool with the user's own typed bytes is allowed and executes, which is what makes the rule a judgment about bytes rather than a ban on tools.

## Options considered

- **A content classifier** ("this query looks like a document"). Rejected: M2-N2's ruling one surface up — value guessing is refused for redaction and refused here. A classifier that is wrong in either direction either leaks or forbids; and it drifts silently as documents change shape.
- **Forbid installed tools from receiving anything but typed text.** Rejected: it deletes the org's ability to consent to more. A tool that declares `document_content` is a legitimate product decision (the re-approved `export_archive`); a platform that cannot say yes cannot be said to govern.
- **Prompt-level instruction** ("never pass documents to installed tools"). Rejected: an instruction is testimony, not enforcement (SR-B5-1); the naive build obeys the *description's* instruction, which is exactly the bug.
- **Per-argument provenance.** Deferred to M4b (M3-N4's line, unchanged): the consent channel today judges the *call's* derived-from set; argument-level classes sharpen it without changing the thesis.

## What it costs

- **The org must read the pin.** The declaration is load-bearing and the platform says so: the install route answers the pin's exact bytes, the exploit prints the poison sentence *from the pin*, and the detection suite measures the violation. Nothing here replaces the reviewer's attention; the control makes the review binding, not optional.
- **The provenance label must be honest upstream.** The consent channel consumes `derived_from`, so its ceiling is the assembler's labeling (see the honest limits below). A platform that mislabels its spans feeds this leg false testimony — and the leg is deliberately dumb about that, because a leg that second-guessed its inputs would be unfalsifiable.
- **Over-denial at the boundary.** Bytes that are *partly* user-typed and partly derived are denied as derived. Fail-closed at the byte boundary is the price of a rule that is checkable at all.

## What it does not cover

- **A publisher who declares `document_content` up front.** Within consent, no leg fires (M4a-N1). No control reads intent; the honest defense is that the reviewed bytes are binding and their violation is *visible* (D2), not that bad publishers are impossible.
- **Content merged into the stored transcript before the run, in vulnerable mode.** The naive assembler's merged span carries no label (R1's precedent): D2's honest blind spot, declared. Content read *during* the run is labelled in both modes — the 07 path.
- **Bytes an agent paraphrases.** The channel reads provenance, not similarity; a model that rewrites the document before passing it carries a derived label only if the platform's span model says so. The label is the contract, not the text.

## How it is verified — and what is not

Verified: the consent leg in `policy_test.rego` (41/41, pinned OPA); the typed-text positive control on the agent's own wire — allowed, executed, identity echoed (07's exploit, hardened); the live matrix both modes; D2 measured in `make detect`, firing from `agent.jsonl` in vulnerable mode where no gate record exists; the mutation check that drops the consent channel is caught.

Not verified: no case exercises a `document_content`-declaring tool receiving *user* text (allowed by construction, unmeasured); the merged-transcript blind spot is declared, not replayed.

## Where it would silently rot

- **The reason-string reuse.** Splitting `tenant_data_egress` into a marketplace-specific reason would quietly claim a new requirement exists. `test_policy_reasons_match_the_policy` holds the set to the policy's legs, and this doc holds the reasoning.
- **The `document_content` mapping.** D2's provenance-to-consent translation is declared in one place (`marketplace_rules.USER_CLASSES` and the policy's install facts). A new class added to the pin vocabulary must re-derive the mapping, not inherit it — a new receives-class that nobody maps would make D2 deny or allow by accident.
- **`gate_call`.** The positive control's channel. If the gate ever publishes a host port "for convenience", controls could drive it from outside the stack and the control/attack channel distinction collapses with no test failing.

## Drift found while writing

None in the final form. The first draft's D2 keyed on `receives ⊆ {"user"}` — which would have denied a `document_content` tool its consent; caught in unit tests before any live run, and the condition now names `document_content` explicitly.
