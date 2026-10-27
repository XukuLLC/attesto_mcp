# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Public functions
remain compatible within 2.x where security permits; security and correctness
fixes may tighten validation or derived defaults in a minor release.

## [2.2.1] - 2026-10-27

### Security

- Require JOSE 1.11.13 or later, which fixes CVE-2026-65625 through
  CVE-2026-65632. AttestoMCP verifies bearer and DPoP-bound tokens through
  Attesto, which with earlier JOSE releases accepted ECDSA signatures padded
  with leading zero bytes.

## [2.2.0] - 2026-10-19

### Added

- `AttestoMCP.Telemetry`: the `[:attesto_mcp, :authenticate]` span around
  every `AttestoMCP.Plug.Authenticate` call and the
  `[:attesto_mcp, :require_scopes]` span around every scope decision. The
  `:stop` metadata carries a bounded `:outcome` (for example
  `:missing_credentials`, `:token_expired`, `:invalid_audience`,
  `:sender_constraint_mismatch`, `:dpop_replay`, `:dpop_nonce_required`,
  `:step_up_required`, `:policy_rejected`, `:insufficient_scope`,
  `:verifier_unavailable`), the refusal's HTTP `:status`, and the
  authenticated `:binding`; an `:exception` event carries only the kind.
  The outcome is also recorded under `conn.private[:attesto_mcp_auth_outcome]`
  and read with `AttestoMCP.Telemetry.outcome/1`.

### Changed

- The plugs install their outcome-recording step as the core `:send_error`
  hook and call the host's own hook from it, so a host hook still renders
  every refusal. `init/1` output now carries that wrapper in place of the raw
  hook.
- Depend on `telemetry ~> 1.0` directly.

## [2.1.2] - 2026-10-18

### Changed

- Require Attesto `>= 2.6.1 and < 3.0.0`, so the resource server's
  pre-authentication JSON nesting and bearer-token size bounds ship with every
  deployment instead of being a recommendation.

## [2.1.1] - 2026-10-18

### Changed

- Serve the protected-resource metadata document with
  `Cache-Control: public, max-age=3600`, the policy AttestoPhoenix applies to
  the same document, instead of `no-store`. The document carries no secrets and
  is identical for every caller, and RFC 9728 §3.1 permits caching it.

## [2.1.0] - 2026-10-18

### Security

- Require a canonical `:base_url` or `:origin` when
  `resource_audience: :resource` is enabled. The access-token audience can no
  longer be derived from the request `Host`, and malformed literal pins or
  callback results fail closed instead of falling back to it.
- Require every router-mounted protected-resource document to identify its
  authorization server through `:config`, `:issuer`, or
  `:authorization_servers`. Metadata never advertises the request authority as
  the authorization server.
- Validate literal `:resource_metadata_url` values during plug initialization.
  Invalid callback results are omitted with a bounded warning and use a valid
  configured fallback when one exists.

### Changed

- Require Attesto `>= 2.6.0 and < 3.0.0`, keeping the MCP boundary on the
  security-hardened core release.
- Require `--base-url` in `mix attesto_mcp.install` and emit the canonical URL
  into both the protection pipeline and metadata declaration. The generated
  metadata declaration also receives the configured Attesto callback.
- Generate `resource_path:` in protected-resource pipelines. The ambiguous
  `resource:` path alias remains accepted with a deprecation warning;
  `Metadata` continues to use `resource:` for the absolute RFC 9728 identifier.
- Normalize and validate resource paths through one implementation shared by
  metadata routing, challenge URLs, audience checks, and the installer.
- Reuse the options normalized by core authentication on every request and for
  scope failures, avoiding repeated policy validation and metadata-resolver
  construction.
- Serve protected-resource metadata with `Cache-Control: no-store`.

### Fixed

- Compile the shipped `AttestoMCP.Test` factory, replay callback,
  and DPoP assertions deterministically in dependency builds, independent of
  the Mix environment or ExUnit module load order. The factory now registers
  cleanup before changing the static keystore and restores any prior setting.

### Deprecated

- Deprecate the compatibility helpers
  `AttestoMCP.Plug.Authenticate.metadata_www_authenticate/1`,
  `AttestoMCP.Metadata.authorization_server/2`,
  `AttestoMCP.Metadata.resource_metadata_param/1`,
  `AttestoMCP.Metadata.append_resource_metadata/2`, and the connection-only
  `AttestoMCP.Metadata.protected_resource_url/2`. They remain callable
  throughout the 2.x line. Use core's native
  `:resource_metadata` option, `Attesto.Discovery.metadata/2`, or
  `protected_resource_url/3` as appropriate.
- Retain the hidden 2.x metadata option, callback fallback, and router path
  helpers as compatibility entry points while routing new code through the
  hardened metadata boundary.

## [2.0.0] - 2026-10-17

### Breaking

- Require Attesto `>= 2.5.0 and < 3.0.0`. Protected-resource metadata and
  challenge URLs now delegate to the shared core metadata and URI policies;
  the former Attesto 1.x compatibility range cannot provide those APIs.
- Require HTTPS protected-resource identifiers and challenge URLs by default.
  Local development endpoints must opt in explicitly with `allow_http: true`.
- Rename the optional Anubis Ecto session table from `attesto_mcp_sessions` to
  `attesto_mcp_anubis_sessions`. Existing Anubis deployments must stop old
  writers and apply the reversible table, constraint, and index rename in the
  README before starting upgraded nodes. A rolling mixed-version deployment is
  not supported for this migration.

### Security

- Validate generated and callback-supplied RFC 9728 metadata pointers with
  Attesto's strict URI policy before adding them to authentication or scope
  challenges. Host `:www_authenticate` callbacks remain total overrides.
- Reject wildcard route requirements before authorization rather than allowing
  a configuration that no concrete grant can satisfy under the core scope
  catalog.

### Changed

- Build RFC 9728 protected-resource metadata through
  `Attesto.ProtectedResourceMetadata`, including `acr_values_supported`, while
  retaining MCP defaults for bearer methods, DPoP algorithms, and scopes.
- Let core resolve function and MFA Attesto config callbacks, removing the
  duplicate MCP-specific resolution path.

### Fixed

- Thread `resource_metadata` and the development-only `allow_http` option
  consistently through token, principal, unauthenticated, and
  insufficient-scope failures.
- Serialize request-derived origins as URIs so IPv6 host literals are bracketed
  in resource identifiers and protected-resource metadata URLs.
- Preserve the normalized options returned by the core authentication plug,
  including parsed RFC 9470 step-up requirements.
- Preserve the documented bare scope-list form in `RequireScopes.init/1` while
  capturing transport options from keyword configuration.
- Exclude the shipped `AttestoMCP.Test.*` helpers from production compilation;
  they remain available in development and test environments.

## [1.4.0] - 2026-10-15

### Security

- Bind Anubis callbacks within a live session to the first issuer, subject, and
  OAuth client that reaches a host callback; support string-keyed contexts and
  custom context keys. The guard fails closed as an Anubis request/session error.
  It cannot bind the original initializer or cover initialization, GET/SSE,
  DELETE, and recovery actions that Anubis performs before callbacks; Anubis
  2.0's normal HTTP recovery path also does not restore saved frame assigns.
- Validate and bound Ecto session identifiers before queries, normalize driver
  failures across every store callback, and sanitize values with Postgrex's
  configured JSON library, including NUL and improper-list handling.
- Validate protected-resource and authorization-server metadata identifiers and
  reject ambiguous, duplicate, or wildcard route-scope requirements. Resource
  identifiers must be absolute HTTP(S) URIs and authorization-server identifiers
  must use HTTPS.
- Refresh the development and CI dependency lock to Decimal 3.2.0, which fixes
  the unbounded-allocation advisory affecting Decimal 3.1.1.

### Fixed

- Require `--config-module` in `mix attesto_mcp.install` and emit the resulting
  config MFA in generated `ProtectResource` pipelines.
- Normalize router resource paths, reject metadata declarations under prefixed
  Phoenix scopes, produce the canonical root well-known URL, clear stale nil
  principals, and handle invalid metadata-URL callback results without raising.

### Changed

- Coordinate this release with Attesto 2.4.0 or later in the 2.x line so the
  delegated JOSE, credential, presentation, and scope checks include the current
  security hardening. The existing Attesto 1.x package range remains supported.
- Always assign the configured principal key after successful authentication,
  including `nil`, so session transports clear a stale principal rather than
  retaining one from an earlier request.
- Add `put_auth/2`, installer `--config-module` / `--config-function` options,
  and a configurable JSON library for the optional Ecto session adapter.

## [1.3.2] - 2026-10-04

### Security

- Normalize Ecto session persistence failures to a fixed error and log message,
  preventing session identifiers, changesets, driver exceptions, or embedded
  private values from reaching logs or caller-visible errors.
- Keep Attesto 1.x compatibility. Deploy with Attesto 2.2.2 or later in the 2.x
  line to include hardening of delegated core JOSE and credential verification.

## [1.3.1] - 2026-10-03

### Changed

- Keep Hex dependency declarations during package tasks even when
  `ATTESTO_PATH` is inherited from a source-development shell.

### Security

- Exclude vulnerable Igniter releases and require patched Mint whenever the
  optional installer/HTTP dependency graph includes it. Update the lockfile
  to patched versions without adding them to neutral runtime consumers.

## [1.3.0] - 2026-08-31

### Changed

- Support both Attesto 1.x and 2.x. Attesto 2.0 changes authorization-server
  storage contracts that this resource-server package does not implement; the
  token, DPoP, mTLS, scope, and Plug APIs used here remain compatible.
- The published package dependency is `>= 1.12.2 and < 3.0.0`, so ordinary Hex
  resolution can select either supported Attesto major line. No MCP application
  migration is required; source checkouts may opt into the coordinated Attesto
  2 path with `ATTESTO_PATH=1`.
- Keep the optional Anubis compatibility bridge available with Anubis MCP 1.x
  and 2.x (`>= 1.7.0 and < 3.0.0`).

## [1.2.2] - 2026-08-27

### Documentation

- Recommend `attesto_mcp_server` as the primary full-server path from the
  README, HexDocs landing module, package links, and wiring guide.
- Move the retained Anubis bridge and infrastructure adapters into an explicit
  optional-compatibility section for existing deployments.

## [1.2.1] - 2026-08-26

### Documentation

- Link to `attesto_mcp_server`, the complete Attesto-native server built on
  this package, and identify its supported MCP protocol eras and transports.

## [1.2.0] - 2026-08-25

### Added

- Add an explicit two-phase `ProtectResource` API for endpoints that classify a
  bounded request envelope before selecting per-operation scopes. It performs
  Attesto authentication once, then enforces the selected scopes through
  `RequireScopes` before dispatch.

## [1.1.0] - 2026-08-11

### Security

- Require `attesto >= 1.12.2`, so MCP resource servers cannot resolve a core
  release predating raw RSA-key denial-of-service bounds and the current token,
  DPoP, parser, and wallet hardening.
- Remove the stale, unused Bandit lock entry affected by the WebSocket
  fragmentation advisory and refresh Postgrex past its stream-comment advisory.
  Neither dependency enters the package's runtime closure, but CI and
  integration environments no longer retain an affected release.

## [1.0.5] - 2026-07-25

### Security

- Encode the security-fixed floor for every supported Plug minor line from
  1.16 through 1.20, retaining broad compatibility without permitting affected
  patch releases between a single lower and upper bound.
- Require Postgrex 0.22.3 or newer in the package's test environment, excluding
  releases affected by the notification reconnect replay vulnerability. This
  dependency remains test-only and does not enter a consumer's dependency tree.

### Changed

- Requires `attesto >= 1.3.0 and < 2.0.0`. The floor carries the same optional
  Plug security branches and JOSE 1.11.12 boundary as 1.2.5, and adds key-bound
  algorithm validation to every verification path this package uses: a DPoP
  proof key must be an RSA key of at least 2048 bits for every accepted RSASSA
  and RSA-PSS algorithm, and a trusted algorithm can no longer be paired with an
  incompatible key type or curve.
- The optional installer integration now requires Igniter 0.6.0 or newer, and
  the optional Anubis bridge requires Anubis MCP 1.7.0 or newer. Both retain a
  next-major upper bound.

### Documentation

- Describe the optional Horde registry in terms of its cluster-wide session
  uniqueness and routing. Anubis MCP 1.7.0 fixed its own dynamic session-name
  fallback, so Horde is no longer presented as compensating for that issue.

## [1.0.4] - 2026-07-16

### Security

- Per-resource audience confinement now delegates to Attesto 1.2.2's strict
  `:trusted_audiences` policy. A scalar token audience must match the protected
  resource, and every member of an array-valued audience must match, so adding
  an untrusted sibling audience can no longer bypass route confinement.
- `:resource_audience` and a caller-supplied core `:trusted_audiences` policy
  are now mutually exclusive and fail closed during plug initialization instead
  of allowing one policy to replace the other. Invalid static policies fail at
  initialization, and a callback returning `nil` or another malformed value can
  no longer disable route confinement for that request.
- Require patched Plug branches (`1.19.5+` within 1.19 or `1.20.3+`) and,
  when the optional Phoenix integration is used, patched Phoenix branches
  (`1.7.24+` within 1.7 or `1.8.9+`). This excludes the intervening releases
  affected by published denial-of-service and cookie-injection advisories even
  when an existing consumer lock would otherwise retain them.

### Changed

- Requires `attesto >= 1.2.2 and < 2.0.0` for strict trusted-audience
  verification.

## [1.0.3] - 2026-07-15

### Fixed

- `mix attesto_mcp.install` now emits the public protected-resource metadata
  macro with an explicit safe `root: false`, makes real repeated installs
  idempotent, keeps distinct resource paths on collision-resistant protection
  pipelines, and generates `resource:` plus `resource_audience: :resource` so
  metadata, requested resources, token audiences, and validated audiences stay
  aligned. Its notice now calls out request-derived origins and reverse-proxy
  pinning.
- The installer now rejects empty scopes and degenerate resource paths, and
  stops safely when an existing metadata declaration uses a non-literal path
  that cannot be compared without evaluating host code.
- Multi-resource routers now reject a later `root: false` declaration when an
  earlier resource already auto-mounted the compatibility root, closing the
  remaining declaration-order-dependent root case.

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
    tuple), coordinates cluster-wide session-name ownership, and routes a
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
