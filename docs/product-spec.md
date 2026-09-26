# BrokenBazaar — Product Spec

> **BrokenBazaar is a deliberately vulnerable application, published as a security learning resource for security practitioners.** Localhost only. See [SECURITY.md](../SECURITY.md).

This document describes BrokenBazaar **as a product**, the way a spec would be written if it were real. It deliberately contains no threat analysis: the threat model (`threat-models/v0-baseline.md`) is derived *from* this document, and that derivation only works if the spec is an honest description of intended behaviour rather than a list of things we already know are wrong.

Where a design here is naive, it is naive the way real products are naive. That is the point.

---

## 1. What BrokenBazaar is

BrokenBazaar is a **multi-tenant AI agent platform with a marketplace**.

An organisation signs up, invites its people, and uploads documents. Each organisation gets an **agent** that can answer questions and do work against those documents. The agent's capabilities are not fixed: the organisation installs **tools** from a catalog of third-party integrations, and the agent can then use them.

The catalog is open. Anyone can register as a **publisher** and list a tool. Tools come in two forms:

- an **MCP server** — a running service exposing callable tools over the Model Context Protocol
- a **skill bundle** — a `SKILL.md` file (plus optional scripts and reference links) that teaches the agent a procedure

The product proposition is the combination: a capable agent, over your own data, extended by an ecosystem you don't have to build.

### Positioning, in one line

*"Your team's AI assistant, with an app store."*

---

## 2. Users and jobs to be done

| Who | What they are trying to do |
|---|---|
| **Org admin** | Get the team set up, control who can do what, decide which tools are allowed |
| **Org member** | Ask the agent to do real work over the org's documents |
| **Org viewer** | Read and ask questions; not change anything |
| **Publisher** | List a tool, get it installed by orgs, iterate on it |

---

## 3. Principals

Five principals. Everything in the system acts as exactly one of them, and every API call resolves to one.

### 3.1 Org (tenant)
The unit of isolation and of billing-in-principle. Owns users, documents, installed tools, and agent configuration. Orgs never see each other's data.

### 3.2 User
A person, belonging to one or more orgs through a **membership**. The membership carries the role — a user can be an admin in one org and a viewer in another.

| Role | Can |
|---|---|
| `admin` | everything a member can, plus manage memberships, install/remove tools, change agent config |
| `member` | create, read, update and delete documents; run the agent |
| `viewer` | read documents; run the agent for read-only work |

### 3.3 Agent session
A single conversation between a user and the agent. **A session is its own principal** — it has an identity, it is created on behalf of a user, and it is what actually calls tools. It is not the user, and the distinction matters: a session is long-lived relative to a request, it acts while the user is not watching, and its actions are attributed to it in the audit record.

### 3.4 Tool grant
The join between an org's decision and a user's decision. A tool is usable in a session only when:

- the **org has installed** it (an admin action), **and**
- the **user has authorised** it for their sessions (a per-user action), **and**
- the session was created with it in scope

A grant is therefore a three-way intersection, not a flag.

### 3.5 Publisher
A third party who lists tools in the catalog. Publishers are **not** part of any org, are not vetted, and are trusted by nobody. They can update their listings after publication.

---

## 4. Core objects

```
Org ─┬─< Membership >─ User
     ├─< Document
     ├─< Installation >── CatalogItem ──> Publisher
     └─< AgentSession >─┬─< ToolCall
                        └─< SessionGrant >── Installation
```

| Object | Key fields |
|---|---|
| `org` | id, name, created_at |
| `user` | id, email, display_name |
| `membership` | org_id, user_id, role |
| `document` | id, org_id, title, body, created_by, created_at |
| `publisher` | id, display_name, contact, created_at |
| `catalog_item` | id, publisher_id, type (`mcp_server` \| `skill`), name, description, version, manifest |
| `installation` | id, org_id, catalog_item_id, installed_by, installed_at, pinned_version |
| `agent_session` | id, org_id, acting_for_user_id, created_at, expires_at |
| `session_grant` | session_id, installation_id |
| `tool_call` | id, session_id, tool_name, arguments, decision, result_summary, created_at |

---

## 5. Core flows

### 5.1 Ask the agent
1. User opens a session. The session records which org it belongs to and which user it acts for.
2. User sends a message.
3. The agent loop runs: model → optional tool call → result → model → … until it produces an answer.
4. Every tool call is recorded before it executes, with its arguments and the decision made about it.

### 5.2 Install a tool
1. An org admin browses the catalog and installs an item.
2. For an `mcp_server`: the platform connects and discovers the tools it exposes.
3. For a `skill`: the platform reads the bundle's frontmatter and adds its description to the agent's skill index.
4. Members authorise the installation for their own sessions.

### 5.3 Publish a tool
1. Anyone registers as a publisher.
2. They submit a catalog item: name, description, type, and a manifest (MCP endpoint, or skill bundle).
3. The listing goes live.
4. The publisher can push updates to the listing at any time.

### 5.4 Use a skill
1. The agent holds an index of installed skills — **name, description, and trigger conditions only**.
2. When the model judges a skill relevant, the platform loads the full `SKILL.md` body into the conversation.
3. If the body references external documentation, the agent may fetch it while working.

---

## 6. Feature list by module

Features ship one module at a time; each module is independently runnable.

### M1 — Tenancy & Identity
- Postgres schema: orgs, users, memberships, documents
- JWT issue and verify; `POST /auth/token`
- `GET|POST|PATCH|DELETE /orgs/:org_id/documents`
- Seed data: three orgs, users in each role, documents per org

### M2 — Agent & Tool Gateway
- Agent loop: model → tool call → result → loop
- Built-in tools: `read_document`, `http_fetch`
- Tool-call gateway as a sidecar: every call is evaluated before execution and the audit record is written first
- `mock-metadata` service so cloud-metadata behaviour is reproducible without a cloud account

### M3 — Delegation & Roles
- Roles enforced with real effect (a viewer cannot delete)
- Agent sessions as first-class objects with their own identity
- Per-org tool grants; per-user session authorisation
- Control plane for agent/gateway configuration

### M4a — Marketplace: MCP servers
- Publisher registration and publisher-owned listings
- Catalog: browse, install, uninstall
- MCP client: connect to an installed server, discover its tools, expose them to the agent
- Version pinning on install

### M4b — Marketplace: Skills
- Catalog item `type: skill`
- Skill bundle format: `SKILL.md` with YAML frontmatter (name, description, triggers, declared capabilities), optional `scripts/`, optional external reference URLs
- Skill index (descriptions) and skill loader (bodies)
- Declared capabilities are reconciled against the session's grants

### M5 — Cloud Estate *(optional track)*
- Terraform for a dedicated GCP project: VPC, private subnets, Cloud NAT, Workload Identity Federation, Secret Manager, per-component service accounts, Org Policy constraints
- Deployment to Cloud Run behind Cloud Armor

### M6 — Program
- Pipeline self-assessment, framework mappings, coverage reporting, and the published write-up set

---

## 7. Interface

`curl` and a minimal `htmx` surface. Enough to exercise every flow by hand, and no more.

```
POST   /auth/token
GET    /orgs/:org_id/documents
POST   /orgs/:org_id/documents
GET    /orgs/:org_id/documents/:id
PATCH  /orgs/:org_id/documents/:id
DELETE /orgs/:org_id/documents/:id

POST   /sessions
POST   /sessions/:id/messages

GET    /catalog
POST   /catalog                        (publisher)
PATCH  /catalog/:id                    (publisher)
POST   /orgs/:org_id/installations
DELETE /orgs/:org_id/installations/:id
POST   /sessions/:id/grants

GET    /healthz
```

---

## 8. Stated assumptions

The assumptions this product is built on. They are written down so the threat model has something concrete to test — some will hold, some will not.

1. A user's membership role reflects what they are allowed to do in that org.
2. An agent session acts within the authority of the user it was created for.
3. Documents belong to exactly one org and are reachable only within it.
4. A tool does what its description says it does.
5. A catalog listing behaves the same after installation as it did at review time.
6. Content the agent reads — documents, fetched pages, tool output — is *data*.
7. Content the agent loads as a skill is *instructions*, and following it is correct behaviour.
8. Configuration and policy are changed only by people entitled to change them.
9. The audit record is a faithful account of what the agent did.

---

## 9. Non-goals

Explicitly out of scope. These are not oversights, and PRs adding them will be declined — every one of them is a large surface that adds no teaching value here.

| Not building | Why |
|---|---|
| **Billing / payments** | Large surface, nothing agent-specific |
| **Email delivery** | Invites and resets are seeded directly in the database |
| **SSO / OIDC / SAML** | Local JWT only; federation is a different lab |
| **Password reset flows** | No email, therefore no reset |
| **Frontend beyond curl/htmx** | The interesting behaviour is server-side; a SPA would only add noise |
| **Real LLM provider dependency in CI** | The agent loop must be runnable deterministically and offline |
| **Multi-region / HA / scale** | The lab is about correctness of authority, not availability |
| **Mobile clients** | — |
| **Web-tier vulnerability breadth** | Covered well by general-purpose vulnerable web apps; not this project's trade |

---

## 10. Definition of "working"

The product is working, for any module, when:

- `make up` brings the stack up from a clean clone with Docker alone
- the seeded data lets every flow in §5 be exercised with `curl`
- `make harden` restarts the same stack with defences enabled and the flows still work
- the module's tests pass in both modes
