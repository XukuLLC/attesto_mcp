# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0] - 2026-06-21

### Changed

- **MCP protected-resource authentication defaults to header-only bearer
  credentials.** `AttestoMCP.Plug.Authenticate` and `ProtectResource` pass
  `bearer_methods: [:header]` to attesto core unless the host opts in with
  `bearer_methods: [:header, :body]`. This matches the MCP protected-resource
  metadata default of `bearer_methods_supported: ["header"]`. **Requires
  `attesto ~> 0.9`.**

## [0.7.0] - 2026-06-21

### Added

- **`AttestoMCP.Anubis.put_auth/1`** — an optional bridge that projects the
  verified `:attesto_context` into an Anubis MCP server's `frame.context.auth`,
  so Anubis's framework-level authorization (the `tools/list` visibility filter,
  per-tool scope gates) sees the resource-server identity. `anubis_mcp` is an
  optional dependency and the module is compile-guarded on `Anubis.Server.Frame`,
  so a resource server that does not use Anubis never compiles it or pulls it in.
  The projection is purely mechanical — no scope-superset, role, or visibility
  policy, which stay in the host app.
- **`AttestoMCP.Plug.Authenticate` now assigns `:attesto_context`** — a single
  protocol-shaped context map (`%{subject, client_id, scope, claims, cnf,
  principal}`), identical to the one `AttestoPhoenix.Plug.Authenticate` assigns,
  under the new `:context_key` option (default `:attesto_context`). This is the
  canonical cross-plug auth context the Anubis bridge reads, so the bridge works
  whether a request was authenticated by the MCP plug or the Phoenix plug.

### Changed

- **MCP scope-rejection rendering now delegates fully to attesto core.**
  `AttestoMCP.Plug.RequireScopes` renders its 403 `insufficient_scope` through
  `Attesto.Plug.OAuthError.insufficient_scope/4`, which now honors the
  `:send_error` / `:www_authenticate` / `:no_store` transport hooks. This removes
  the local 403 gap-filler and the `AttestoMCP.Plug.Error` shim (the on-the-wire
  challenge and body are unchanged). **Requires `attesto ~> 0.8.1`.**
- **The `:no_store` transport hook** now threads through `RequireScopes` and
  `ProtectResource`, at parity with `:send_error` / `:www_authenticate`.

### Fixed

- The `mix attesto_mcp.install` tests declare `phx_new` (test-only) so
  `Igniter.Test.phx_test_project/1` has the Phoenix project generator
  (Igniter.Phoenix.Single, compile-guarded on Phx.New.Project) it needs.

## [0.6.2] - 2026-06-14

### Fixed

- **The `mix attesto_mcp.install` task no longer references `Igniter.Mix.Task`
  unconditionally, so attesto_mcp compiles in a consumer that does not depend on
  `igniter`.** `igniter` is an optional dependency, but the install task did
  `use Igniter.Mix.Task` at the top level. In a consumer application that
  depends on attesto_mcp without also pulling in `igniter` (the common prod
  case), compiling attesto_mcp failed with `module Igniter.Mix.Task is not
  loaded and could not be found`. The task is now wrapped in a top-level
  `if Code.ensure_loaded?(Igniter)` guard: the Igniter-backed installer compiles
  only when `igniter` is present, and a `use Mix.Task` fallback that prints a
  "install igniter to use this task" message takes its place otherwise. Behavior
  is unchanged when `igniter` is available.

## [0.6.1] - 2026-06-14

### Fixed

- **`AttestoMCP.Plug.ProtectResource` can again be used as a compile-time router
  pipeline plug (`plug_init_mode: :compile`).** 0.6.0 made `init/1` bake the
  generated `resource_metadata` `WWW-Authenticate` closure into the
  `RequireScopes` transport. Under `:compile` mode (the Phoenix router /
  production default) a plug's `init/1` result is embedded via `Macro.escape`,
  which rejects anonymous functions, so a router carrying the plug failed to
  compile. The generated challenge is now built at **call** time from an
  escape-safe spec (strings / `{m, f}` tuples), so `init/1` returns no closures
  and the plug compiles in a `:compile`-mode pipeline. Behavior is unchanged: an
  insufficient-scope 403 still carries the `resource_metadata` pointer, and a
  host-supplied `:www_authenticate` still wins. (Callbacks the host passes to the
  plug must be remote captures or MFA tuples, not anonymous `fn`, to be embedded
  under `:compile` mode — the same constraint Plug imposes on every plug.)

## [0.6.0] - 2026-06-14

### Added

- **Origin pinning for protected-resource metadata behind a proxy.** A host can
  now pin the advertised `resource`/challenge origin and `authorization_servers`
  instead of always deriving them from the live request connection, which behind
  a TLS-terminating proxy is both fragile (`http`/internal host) and an
  `X-Forwarded-Host` spoofing vector into the metadata document a client trusts
  to find its authorization server.
  - `AttestoMCP.Metadata.resolve_origin/2` resolves the resource server origin:
    an explicit `:base_url`/`:origin` (a `String.t()` or `(conn -> url)`) wins
    over the request connection. It drives the `resource` identifier and the
    `protected_resource_url/3` challenge URL.
  - `AttestoMCP.Metadata.protected_resource/3` now defaults
    `authorization_servers` to the `:config` issuer (or an explicit `:issuer`
    string) when one is given, rather than the resource origin — the issuer is
    the authorization server the host already trusts. The `resource` identifier
    is **not** derived from the issuer (RFC 9728 keeps the two distinct).
  - The router macro `attesto_mcp_protected_resource_metadata`,
    `AttestoMCP.MetadataController`, `AttestoMCP.Plug.Authenticate`, and
    `AttestoMCP.Plug.ProtectResource` all accept and thread `:base_url`/`:origin`
    (and `:issuer`/`:config`), so the served metadata and the
    `WWW-Authenticate` `resource_metadata` challenge stay aligned when pinned.
    `:base_url`/`:origin` accept a string, a `(conn -> url)` callback, or a
    `{module, fun}` / `{module, fun, args}` tuple (so a dynamic origin works in a
    compiled router macro, where an anonymous fn cannot).
  - The generated `resource_metadata` challenge is now emitted consistently on
    every rejection the MCP plugs render - token failure, principal-callback
    rejection (a 401 from `AttestoMCP.Plug.Authenticate`), and insufficient-scope
    rejection (a 403 from `AttestoMCP.Plug.RequireScopes` via `ProtectResource`)
    - so a client is pointed at metadata on all of them, not just token failures.
  - New `guides/proxy_origin.md` documents the pinned-origin recipe so consumers
    do not reinvent a canonical-host guard plug.

### Fixed

- `authorization_servers` advertises the issuer **verbatim**: it is no longer
  trailing-slash-trimmed, since an issuer identifier is compared by exact string
  match (a trimmed path-based issuer would break discovery). The resource origin
  is still trimmed (it is joined with a path). A blank explicit `:issuer` is
  ignored rather than publishing `[""]` or overriding a configured issuer.
- A blank, relative, or non-binary `:base_url`/`:origin` pin (`""`, `"/"`,
  `"/prefix"`, `"mcp.example.com"`, …) is treated as "not configured" and falls
  back (`:base_url` → `:origin` → request origin) instead of producing relative
  or empty security metadata (no more `resource: "/mcp"` or
  `authorization_servers: [""]`). A pin must be an absolute `scheme://…` origin.
- An explicit `:resource` / `:authorization_servers` now short-circuits the
  derivation, so a lower-precedence origin/issuer callback is never invoked (and
  cannot fail) for a value the host supplied outright. The resource origin is
  also resolved at most once per document and shared with the
  `authorization_servers` fallback, so a stateful origin callback cannot make
  the `resource` and `authorization_servers` disagree.

### Changed

- `AttestoMCP.Metadata.protected_resource/3` now sets `resource` with `put_new`
  (was `put`), so an explicit `:resource` opt overrides the derived identifier —
  matching how `:authorization_servers` already behaved.
- With no pinning options supplied, behavior is unchanged: both origins derive
  from the request connection.

## [0.5.2] - 2026-05-31

### Fixed

- Correct the README installation snippet now that the package is published on
  Hex.

## [0.5.1] - 2026-05-31

### Changed

- Reuse `Attesto.Test.DPoP` for MCP DPoP proof fixtures so downstream MCP tests
  stay aligned with Attesto's published DPoP helper API.

## [0.5.0] - 2026-05-31

### Added

- `AttestoMCP.Plug.ProtectResource`: a single plug composing
  `AttestoMCP.Plug.Authenticate` then `AttestoMCP.Plug.RequireScopes` into a
  correctly ordered, halt-respecting pipeline, with the RFC 9728
  `resource_metadata` `WWW-Authenticate` challenge auto-wired from the resource
  path.
- `AttestoMCP.Router` with the `attesto_mcp_protected_resource_metadata/2`
  Phoenix router macro, and `AttestoMCP.MetadataController`, serving
  per-resource `/.well-known/oauth-protected-resource/<path>` metadata plus a
  backwards-compatible root `/.well-known/oauth-protected-resource` route. The
  served `resource` identifier matches the `ProtectResource` challenge.
- `AttestoMCP.Test.DPoPAssertions`: shipped ExUnit assertions for host apps
  proving a DPoP-bound token presented as a plain Bearer is rejected and is
  accepted with a valid DPoP proof.
- `guides/mcp_wiring.md`: copy-pasteable end-to-end wiring guide.
- `phoenix` as an optional dependency (only needed by `AttestoMCP.Router` and
  `AttestoMCP.MetadataController`).
- Initial Plug/Phoenix authentication wrapper for protecting HTTP MCP endpoints
  with Attesto access-token verification, DPoP proof checks, and mTLS
  certificate-bound token checks.
- MCP scope convention helpers.
- OAuth protected-resource metadata builder and authorization-server metadata
  delegation.
- Focused tests for Bearer, DPoP, mTLS, scope enforcement, principal mapping,
  custom error rendering, and public assign names.
