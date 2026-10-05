# Rules for the coding agent

**The rules live in [`AGENTS.md`](AGENTS.md). Read that file.**

This one is a pointer and contains no rules of its own.

Two rule files that both define hardened zones will drift, and the moment they drift an agent can
read whichever is more permissive and remain technically compliant. The same argument this repo
makes about `store.ForOrg(ctx)` applies to its own governance: **a rule that can be satisfied from
two places is a rule you cannot enforce.**

`AGENTS.md` is the canonical name because it is the convention several tools read automatically.
This file exists because Claude Code looks for it.

If you are an agent and you reached this file first: go read `AGENTS.md` before writing anything.
It names zones you may not modify, and modifying one without having read it is not an excuse.
