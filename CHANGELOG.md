# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Fixed

- `mix attesto_mcp.install` now emits the public protected-resource metadata
  macro with an explicit safe `root: false`, makes real repeated installs
  idempotent, keeps distinct resource paths on collision-resistant protection
  pipelines, and generates `resource:` plus `resource_audience: :resource` so
  metadata, requested resources, token audiences, and validated audiences stay
  aligned. Its notice now calls out request-derived origins and reverse-proxy
  pinning.

### Documentation

- Corrected multi-resource root ownership and added the combined
  `attesto_phoenix` authorization-server plus multiple MCP resource pattern.

## [1.0.2] - 2026-07-13

### Changed

- Docs only: RFC 9728 discovery guidance for combined AS+RS apps. The router
  macro and README now spell out how clients actually discover
  protected-resource metadata (the §3.1 path-inserted probe first, then the
  `WWW-Authenticate` `resource_metadata` fallback) and how to give each PRM
  route exactly one owner next to `attesto_phoenix`'s `attesto_routes` — whose
  new `protected_resource_paths`/`protected_resource_root` options
  (attesto_phoenix 1.3.0) cover the single-resource AS+RS case.

## [1.0.1] - 2026-07-08

### Changed

- Requires `attesto ~> 1.2`, picking up the 1.2.x line — including the
  `Attesto.Keystore.Static` fix that labels the signing key's `kid` from
  `:signing_alg` (attesto 1.2.1), so a PS256-signing host verifies its own
  tokens without a redundant `:key_algs` entry. No functional change in
  attesto_mcp itself.

## [1.0.0] - 2026-07-04

First stable release; the public API is now under semantic versioning. No
functional change from 0.11.0. Requires `attesto ~> 1.0`.

## [0.11.0] - 2026-06-23

### Added

- **Clustered + persistent Anubis MCP session infrastructure** (optional,
  compile-guarded — an RS-only consumer pays nothing):
  - `AttestoMCP.Anubis.SessionStore.Ecto` — a Postgres-backed
    `Anubis.Server.Session.Store`. Anubis ships only a Redis adapter; this
    persists the session map (keyed by `Mcp-Session-Id`) so a client reconnects
    after a deploy/node-replacement with its initialized state restored instead
    of re-initializing. Stateless (`start_link/1` is `:ignore`, rides the host
    repo), with lazy + scheduled (`cleanup_expired/1`) TTL reaping. Backed by the
    `AttestoMCP.Anubis.Session` schema; `mix attesto_mcp.gen.session_migration`
    creates the `attesto_mcp_sessions` table. Compile-guarded on `Ecto.Schema`.
  - `AttestoMCP.Anubis.JSONSafe.sanitize/1` — strips non-JSON-encodable values
    (bare structs, pids, refs, tuples, functions) from session state before the
    `jsonb` insert, since Anubis folds the whole request `assigns` into the
    persisted frame; without it the driver raises mid-`initialize` and kills the
    session process.
  - `AttestoMCP.Anubis.Registry.Horde` — a cluster-wide `Anubis.Server.Registry`
    that keeps the client-supplied `session_id` as CRDT/ETS data (a `:via`
    tuple), closing the **atom-table-exhaustion DoS** in the bundled `:pg`
    adapter (which derives a never-GC'd atom per session id), and routes a
    request landing on any node to the node holding the session. Compile-guarded
    on `Horde.Registry`.
  - `mix attesto_mcp.install.sessions` — an Igniter installer that writes the
    `config :anubis_mcp, :session_store` block (and, with `--registry`, adds the
    `horde` dependency), and prints next-step notices for the migration and the
    supervision-tree registry wiring.

## [0.10.0] - 2026-06-22

### Added

- **RFC 9470 Step-Up Authentication.** `AttestoMCP.Plug.ProtectResource` /
  `Plug.Authenticate` accept a per-route `:step_up` requirement
  (`[acr_values: [...], max_age: ...]`); after the token is verified its
  `acr` / `auth_time` claims must satisfy it or the request is refused 401
  `insufficient_user_authentication` naming what the client must re-request.
- `attesto_mcp_protected_resource_metadata/2` accepts `root: true | false` to
  control the unsuffixed RFC 9728 root compatibility document explicitly.

### Changed

- The root `/.well-known/oauth-protected-resource` compatibility document is now
  auto-mounted only for a **single-resource** router. Once more than one
  resource is declared its resource is ambiguous, so the host must choose with
  `root: true` (nominate the resource) or `root: false` (serve no root); a second
  resource that leaves the root implicit is a compile error. Previously the root
  silently resolved to whichever resource was declared first, which could publish
  a sensitive resource's metadata at a guessable path by accident.

## [0.9.0] - 2026-06-22

### Added

- **RFC 8707 / RFC 9728 per-resource audience confinement.**
  `AttestoMCP.Plug.ProtectResource` / `Plug.Authenticate` gain a
  `:resource_audience` option: with `:resource` (or a string / `(conn -> uri)` /
  `{m, f}` value) the access token's `aud` is validated against THIS resource's
  identifier rather than the host's global `config.audience`, so a token minted
  for a sibling resource is rejected (audience confinement, RFC 8707 §1).
- `AttestoMCP.Metadata.resource_identifier/3` — the single canonical
  origin-plus-path identifier shared by the advertised metadata `resource` and
  the validated audience, so `metadata.resource == requested resource == minted
  aud == validated aud` holds by construction.

### Changed

- Requires `attesto ~> 0.10`. `:resource_audience: :resource` raises (fails
  closed) when no resource path is configured to derive the identifier from.

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
