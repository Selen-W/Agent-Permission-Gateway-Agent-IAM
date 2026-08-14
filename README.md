<div align="center">

<img src="assets/logo.svg" alt="Agent Permission Gateway" width="120" />

# Agent Permission Gateway / Agent IAM

**The underlying question: *what is an agent permitted to do?***

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/Selen-W/AbertJob/ci.yml?branch=main&label=CI)](.github/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-86%25-brightgreen)](#development)
[![Node](https://img.shields.io/badge/node-%3E%3D18-339933)](#development)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Stars](https://img.shields.io/github/stars/Selen-W/AbertJob?style=social)](https://github.com/Selen-W/AbertJob)

*English | [简体中文](README_zh.md)*

*IAM + policy firewall + approval workflow + audit log for AI agents*

</div>

Once an agent can invoke shells, filesystems, GitHub, databases, cloud services, browsers, and
payment APIs, permission control ceases to be a matter of confirmation dialogs. It becomes part of
the agent infrastructure itself.

This project is not a confirmation-dialog plugin. It is an **Agent Permission Gateway** that sits
in front of every tool call an agent makes:

```text
                    User
                     │
                     ▼
                AI Agent
                     │
             Tool / Action
                     │
                     ▼
        ┌──────────────────────┐
        │ Agent Permission     │
        │ Gateway              │
        ├──────────────────────┤
        │ Identity  (WHO)      │
        │ Policy    (WHAT)     │
        │ Risk      (WHY/WHEN) │
        │ Approval  (scoped)   │
        │ Audit               │
        └──────────┬───────────┘
                   │
                   ▼
         ALLOW / DENY / ASK
```

The governing principle: **an agent does not own permissions.** An agent requests permission; the
gateway decides whether to grant it.

**Highlights**

- 🚦 Three decisions: **ALLOW / DENY / ASK** (ASK routes through the host approval channel)
- 🧠 Five-dimension risk engine: **WHO / WHAT / WHERE / WHEN / WHY** → 0–100 explainable score
- 📜 Declarative YAML policy: define the capability boundary up front instead of approving each call
- ⏱️ Scoped grants: **Approve once ≠ Always allow** (Action + Resource + Scope + Time)
- 🧾 Full audit trail: session-log events + process-wide audit ring + session projection
- 🔌 Zero runtime dependencies; a standard Cordis plugin, mountable as-is

## Quick Start

```sh
pnpm install
pnpm exec tsx examples/demo.ts     # end-to-end demo: decisions and risk breakdown per rule
pnpm run check                     # typecheck + 103 tests
```

Mount into dsh (`cordis.patch.yml`):

```yaml
plugins:
  permission-gateway:
    $apply: ./agent_job_permission_dev/src/index.ts
    policy: |
      agent: coding-agent
      default_decision: ask
      permissions:
        shell:
          allow: ["git status", "git diff", "npm test"]
          deny:  ["sudo", "rm -rf /"]
```

The plugin is usable with no policy at all: it fails closed by default (`ask` posture, calls at or
above risk 80 rejected outright).

## Core Concepts

### 1. Three decisions

| Decision | Meaning | Example |
|---|---|---|
| **ALLOW** | Execute immediately | `read_file("readme.md")` — matched an allow entry |
| **ASK** | Route through the approval flow | `git push origin main` — matched an approval entry / production policy |
| **DENY** | Reject, with a reason | `rm -rf /` — matched a deny entry / risk ceiling |

### 2. Risk is more than the command

`git = allowed / rm = denied` is the wrong model: pushing to `feature/*` and pushing to a
production branch carry entirely different risk. The engine therefore evaluates five dimensions
simultaneously:

| Dimension | Signal | Effect on risk |
|---|---|---|
| **WHO** | Which agent / operator / session | Unrecognized principal +5; the operator −5 |
| **WHAT** | read / write / execute / delete / network / deploy | Base score 0 → 30 |
| **WHERE** | workspace / repository / database / **production** | Sensitivity 0 → 45 |
| **WHEN** | Inside or outside the production window | +20 outside the window |
| **WHY** | Overlap between the task keywords and the action | +15 on mismatch (e.g. deleting a production bucket while tasked to fix tests) |

Risk is **evidence**, not a verdict — the decision belongs to the policy engine.

### 3. Declarative policy

```yaml
agent: coding-agent
default_decision: ask
operator: alice
permissions:
  filesystem:
    read:   ["./workspace/**"]
    write:  ["./workspace/**"]
    delete: ["./workspace/tmp/**"]
  shell:
    allow:    ["git status", "git diff", "mvn test", "npm test"]
    approval: ["git commit", "git push"]
    deny:     ["sudo", "rm -rf /"]
  network:
    allow: ["github.com", "registry.npmjs.org"]
    deny:  ["*"]          # default-deny: hosts not listed are rejected
  production:
    require_approval: true
    protected_branches: ["main", "master", "prod/*"]
    window: ["09:00-18:00 Mon-Fri"]
```

Rule semantics:

- Commands match by **token prefix** (`git push` matches `git push origin main`, not `git pushy`)
- Default precedence is **deny > approval > allow**; `deny: ["*"]` switches to allowlist mode
  (allow entries take precedence, everything else falls to the deny tail)
- **Capability specificity**: repository / database / deploy / network rules are evaluated before
  the generic shell rules, so `git push --force` (deny) overrides `git push` (approval)
- With no rule matched and risk ≥ `deny_risk_above` (default 80), the call is denied by the risk
  ceiling; an explicit rule match overrides the ceiling

### 4. Approval and scoped grants

On ASK, the host approval channel presents the request:

```text
⚠️ Approval Required
──────────────────────────────
Agent: coding-agent
User:  Alice
Action: git push origin main
Risk:   HIGH
Reason: Modifies protected branch
[Approve once]  [Always allow]  [Reject]
```

The key design point: **Approve once ≠ Always allow**. "Always allow" is a bounded grant:

```text
git push                                  (Action)
+ repository = github.com/company/project-a (Resource)
+ branch     = feature/*                  (Scope)
+ duration   = 1 hour                     (Time)
```

A grant takes effect only when Action + Resource + Scope + Time are all satisfied, and expires
automatically. Calls covered by an active grant are allowed directly, without prompting the
operator (`approval/request` short-circuit).

### 5. Audit

Every call that reaches the gateway is recorded in:

- Session-log events `permission/gateway-decision` (log-only; **never appears in model context**)
- A process-wide audit ring (500 entries by default; `service.recentAudit()`)
- The `permissionGateway` session projection (latest 50 entries; shared by browser panels and
  replay)

## Documentation

| Document | Contents |
|---|---|
| [**Usage Manual**](docs/使用手册.md) | Full reference (Chinese): mounting, every configuration field, policy syntax, risk engine, approval and grants, audit, programming interface, scenarios, FAQ |
| [**Example Policy**](examples/policy.example.yaml) | An annotated, complete capability boundary |
| [**End-to-end Demo**](examples/demo.ts) | Runnable demo: verdicts, risk breakdown, grant short-circuit |
| [**Changelog**](CHANGELOG.md) | Release history and roadmap |
| [**Contributing**](CONTRIBUTING.md) | Code of conduct, environment setup, PR workflow |
| [**Security**](SECURITY.md) | Vulnerability reporting and security design commitments |
| [**简体中文 README**](README_zh.md) | 中文版说明 |

## Project Layout

```text
src/
  types.ts      # Public vocabulary (compatible with dsh permission-gateway/types)
  glob.ts       # Glob / command-token / host matching
  yaml.ts       # YAML-subset parser for policies (fails loud, never silent)
  context.ts    # Tool call → WHO/WHAT/WHERE/WHEN/WHY signal extraction
  risk.ts       # Risk engine (0–100 score, bands, explainable contributions)
  policy.ts     # Declarative policy → ordered rules
  grants.ts     # Scoped grants (Action + Resource + Scope + Time)
  audit.ts      # Bounded audit ring
  engine.ts     # Decision engine: risk + rules + grants → verdict
  host.ts       # Structural host contract (tools / approval / session / …)
  service.ts    # Gateway service (judge / summary / audit / grants)
  index.ts      # Cordis plugin entry (apply)
examples/       # Example policy + demo
docs/           # Usage manual
tests/          # 103 unit tests (incl. end-to-end against a mocked host)
```

## Development

```sh
pnpm install
pnpm run typecheck      # tsc --noEmit
pnpm run test           # vitest
pnpm run test:coverage  # coverage report
pnpm run check          # typecheck + test
pnpm run demo           # end-to-end demo
```

`tests/plugin.spec.ts` verifies the plugin end to end against a mocked Cordis context:
`tools/pre-execute` interception, grant short-circuit in the approval channel, audit events in the
session log, and live policy reload.

## Design Decisions

- **The risk engine is heuristic**: it produces evidence only; the verdict always rests with the
  policy and the operator
- **The parser fails loud**: YAML is a security boundary — a misread `*` can open the wrong door,
  so unsupported constructs throw with a line number instead of being silently misparsed
- **`deny: ["*"]` has dedicated semantics**: "default deny" (allow takes precedence) is distinct
  from a specific prohibition (which overrides allow)
- **Fail closed by default**: without an approval channel ASK degrades to DENY; without a matching
  rule, the `deny_risk_above` ceiling protects the deployment

---

*For the full reference — every configuration field, the risk score tables, the approval and grant
APIs, scenarios, and FAQ — see the [Usage Manual](docs/使用手册.md) (Chinese).*

## License

[MIT](LICENSE) © [AbertJob](https://github.com/Selen-W)
