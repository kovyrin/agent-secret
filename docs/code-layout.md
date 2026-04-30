# Code Layout

Status: scaffold decision record.

Agent Secret Broker should behave like a standalone project from the first
implementation commit. It must not depend on any host application as a runtime
or build dependency.

## Selected Layout

```text
agent-secret/
  cmd/agent-secret/              # Go CLI entrypoint
  cmd/agent-secretd/             # Go daemon entrypoint
  internal/                      # Private Go packages
    approval/                    # Approval request/response contracts
    audit/                       # Metadata-only JSONL audit writer
    cli/                         # CLI parsing and help text
    daemon/                      # Daemon lifecycle and request orchestration
    op/                          # 1Password SDK adapter
    policy/                      # Request validation, reuse, TTL, sessions
    profileconfig/               # Project-local profile config loading
    socket/                      # Unix socket protocol and peer metadata
    supervisor/                  # CLI-owned child process supervision
  approver/                      # SwiftUI/AppKit macOS approval app
  docs/                          # Product, architecture, and implementation docs
```

The Go module path is `github.com/kovyrin/agent-secret`. That keeps imports,
examples, and future public documentation stable.

## Swift Approver Boundary

The approver starts as a minimal real macOS `.app` bundle in `approver/`, built
with SwiftUI/AppKit. It should keep a stable bundle identity, request view model,
socket protocol client, and `os.Logger` diagnostics boundary so it can later
grow into a menu bar app without replacing the approval integration.

The approver is not a secret resolver. It receives approval metadata only and
must not fetch, store, print, or log secret values.

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
- Adding unvalidated runtime dependencies during scaffold work: rejected until
  the SDK, socket, and approver research spikes prove the assumptions.
