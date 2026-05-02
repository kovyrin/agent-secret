# Code Layout

Status: current implementation map.

Agent Secret Broker is a standalone project. Product code, build scripts,
distribution packaging, docs, tests, and CI live in this repository and must not
depend on a host application's runtime code or private project paths.

## Current Layout

```text
agent-secret/
  cmd/
    agent-secret/                # Go CLI entrypoint
    agent-secretd/               # Go daemon entrypoint
  internal/                      # Private Go packages
    audit/                       # Metadata-only JSONL audit writer
    cli/                         # CLI parsing, help text, and command runners
    daemon/                      # Socket protocol, broker, daemon lifecycle,
                                  # approver IPC, cache, and server handlers
    envfile/                     # dotenv-style env file parsing
    execwrap/                    # CLI-owned child process execution and audit
    install/                     # User-level CLI and skill installation helpers
    opresolver/                  # 1Password SDK desktop integration adapter
    peercred/                    # macOS Unix socket peer credential lookup
    policy/                      # Request validation, reuse, TTL, sessions,
                                  # nonces, and value-free policy state
    processhardening/            # Process-level hardening hooks
    profileconfig/               # Project-local profile config loading
    request/                     # Exec request model and secret ref parsing
    secretmem/                   # In-memory secret value handling
  approver/
    Sources/
      AgentSecretApprover/       # Swift approval models, UI, logging, transport
      AgentSecretApproverApp/    # Shipped macOS approver/setup app executable
      AgentSecretApproverSmoke/  # Non-secret smoke executable
    Tests/                       # Swift unit and contract tests
    scripts/                     # Approver app bundle build helpers
  docs/                          # Product, architecture, release, and user docs
  scripts/                       # Project build, lint, install, and release tools
  .github/workflows/             # GitHub Actions CI and release artifact jobs
```

The Go module path is `github.com/kovyrin/agent-secret`. That keeps imports,
examples, and future public documentation stable.

## Go Package Boundaries

`cmd/agent-secret` is a thin entrypoint over `internal/cli`. The CLI parses
requests, starts `agent-secretd` on demand through `daemon.Manager`, asks the
daemon for approved environment payloads, and then uses `execwrap` to spawn and
audit the wrapped child process. The CLI does not resolve 1Password values.

`cmd/agent-secretd` wires the daemon runtime: audit writer, approver launcher,
trusted-client validation, and lazy 1Password resolver construction. The daemon
owns approval ordering, reusable approval/cache state, socket request handling,
1Password fetches after approval, and metadata-only audit events.

`internal/daemon` is the main trust-boundary package. It contains the Unix
socket protocol client/server, daemon manager, broker orchestration,
approver-request queue, process launcher, peer validation hooks, stop/status
handlers, and reusable secret cache. It depends on narrower packages for policy,
request shapes, peer credentials, secret values, and audit output.

`internal/request` defines the value-free request model shared by CLI, daemon,
policy, audit, and protocol code. It parses and validates `op://` reference
syntax but does not contact 1Password.

`internal/policy` validates request rules and tracks reusable approvals,
sessions, use counts, TTLs, and nonces without storing raw secret values.
Reusable approval cache values live in `internal/daemon`, keyed by the policy
scope.

`internal/opresolver` is the only Go package that creates the 1Password SDK
desktop-app integration client and resolves approved refs. Integration tests for
live 1Password access remain opt-in.

`internal/execwrap` owns child process execution from the CLI side. This keeps
normal process supervision, passthrough stdio, signal handling, and
command-start/completion audit reporting outside the daemon.

`internal/peercred` contains the macOS peer credential lookup used by daemon
socket handlers. Peer credential policy decisions stay in `internal/daemon`.

`internal/envfile` parses dotenv-style files before approval so env-file secret
refs become normal request secrets.

`internal/secretmem` holds in-memory secret value primitives used where raw
values are unavoidable after approval. It is deliberately separate from policy
objects and audit data.

## Swift Approver Boundary

The Swift package in `approver/` builds the shipped macOS approver/setup app and
a non-secret smoke executable. The approver receives approval metadata from the
daemon socket, renders a native prompt, logs value-free lifecycle events, and
submits a decision containing the request ID and nonce.

The approver is not a secret resolver. It must not fetch, store, print, or log
secret values.

## Superseded Scaffold Names

The original scaffold proposed package names that no longer exist:

- `internal/approval` is represented by request models in `internal/request`,
  policy state in `internal/policy`, daemon approval IPC in `internal/daemon`,
  and Swift approval models in `approver/Sources/AgentSecretApprover`.
- `internal/op` is now `internal/opresolver`.
- `internal/socket` is folded into `internal/daemon` for protocol handling and
  `internal/peercred` for OS peer metadata.
- `internal/supervisor` is now `internal/execwrap`.

Those names should be treated as historical planning terms, not active package
boundaries.

## Repository Boundary

The repository should remain self-contained:

- preserve the Go module path `github.com/kovyrin/agent-secret`;
- keep project-owned commands, docs, tests, and CI inside this repository;
- avoid imports, scripts, or docs that require external project paths;
- keep consumer-specific integrations outside the core design unless they are
  generic examples.

## Rejected Layouts

- Placing code under host application directories: rejected because this tool
  must not depend on host application runtime code.
- Letting the daemon spawn wrapped commands: rejected because the CLI owns child
  process supervision while the daemon owns approval, 1Password access, cache,
  and audit.
- Starting with session/socket reads as the primary mode: rejected because
  env-only `agent-secret exec` is the first dogfood path.
- Using a throwaway command-line alert helper for approval: rejected because v1
  needs a real app boundary that can grow into a menu bar app.
