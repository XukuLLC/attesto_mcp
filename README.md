# AttestoMCP

[![Hex.pm](https://img.shields.io/hexpm/v/attesto_mcp)](https://hex.pm/packages/attesto_mcp)
[![Hexdocs.pm](https://img.shields.io/badge/docs-hexdocs.pm-blue)](https://hexdocs.pm/attesto_mcp)
[![Elixir CI](https://github.com/XukuLLC/attesto_mcp/actions/workflows/elixir.yml/badge.svg)](https://github.com/XukuLLC/attesto_mcp/actions/workflows/elixir.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](https://github.com/XukuLLC/attesto_mcp/blob/main/LICENSE)
[![Elixir](https://img.shields.io/badge/elixir-%E2%89%A5%201.18-purple)](https://elixir-lang.org)

OAuth resource-server helpers for HTTP MCP servers in Plug/Phoenix: protect the
MCP endpoint, publish OAuth discovery metadata, verify Bearer/DPoP/mTLS access
tokens, enforce scopes, and hand the verified identity to Anubis when your MCP
server runs on Anubis.

## Why use this

An MCP server library gives you tools, prompts, resources, and transport
lifecycle. OAuth still leaves several resource-server chores at the HTTP
boundary:

- Challenge unauthenticated clients with an RFC 9728 `resource_metadata` pointer
  so ChatGPT, Claude, and other MCP clients can discover how to authorize.
- Verify access tokens locally by signature, issuer, audience, expiry, and
  sender constraint.
- Reject DPoP-bound tokens presented as plain Bearer tokens, and reject
  mTLS-bound tokens without matching certificate context.
- Enforce route-level MCP scopes before the request reaches your tools.
- Render OAuth-compatible 401/403 errors through the same host-controlled
  response envelope.
- Put verified subject, client, scopes, and raw claims where downstream MCP code
  can read them.

`attesto_mcp` packages that glue as Plug modules. You still bring the MCP server
implementation and your app's policy.

## If you use Anubis

[Anubis](https://hex.pm/packages/anubis_mcp) already has authorization-aware
helpers such as `Frame.scopes/1`, `Frame.has_scope?/2`, and scope-aware tool
visibility. Those helpers read from `frame.context.auth`. A Plug/Phoenix auth
pipeline, however, naturally verifies the request before the Anubis frame exists.

This package connects those two layers:

1. `AttestoMCP.Plug.ProtectResource` protects `/mcp` before the Anubis transport
   handles the request.
2. The auth plug assigns a neutral `conn.assigns.attesto_context` map containing
   the verified subject, client ID, scopes, claims, confirmation claim, and
   optional host principal.
3. `AttestoMCP.Anubis.put_auth/1` projects that context into
   `frame.context.auth`, the place Anubis expects it.

```elixir
pipeline :mcp_auth do
  plug AttestoMCP.Plug.ProtectResource,
    config: &MyApp.Attesto.config/0,
    replay_check: &MyApp.DPoPReplay.check_and_record/2,
    resource: "/mcp",
    scopes: [AttestoMCP.Scopes.tools_call()]
end

def handle_request(request, frame) do
  frame = AttestoMCP.Anubis.put_auth(frame)
  # Anubis authorization helpers now see the verified subject/scopes/claims.
end
```

That saves an Anubis host from hand-writing token parsing, DPoP proof checks,
protected-resource challenges, scope rejection responses, and the
`frame.context.auth` projection. It does not add role, tenant, admin, or tool
visibility policy; keep that in your app.

`anubis_mcp` is optional. The bridge module compiles only when Anubis is
present, so non-Anubis MCP servers do not take a hard dependency on it.

### Clustered or persistent sessions (optional)

Anubis already covers the common multi-node case itself:
`Anubis.Server.Registry.PG` tracks session pids in a `:pg` scope shared across
connected nodes and routes a request to the node holding the session, and
`Anubis.Server.Session.Store.Redis` persists sessions across restarts. Reach for
those first.

Two optional adapters sit alongside them for hosts whose infrastructure points
elsewhere (both compile-guarded, so an RS-only consumer pulls in neither):

- `AttestoMCP.Anubis.SessionStore.Ecto` — a Postgres-backed
  `Anubis.Server.Session.Store`, for hosts that would rather not run Redis for
  this alone; Redis is the only store Anubis bundles. A client reconnects after
  a node replacement with its initialized state restored. Wire it with
  `mix attesto_mcp.install.sessions`.
- `AttestoMCP.Anubis.Registry.Horde` — an `Anubis.Server.Registry` backed by
  Horde's CRDT-backed name ownership. Cross-node routing is not what this adds;
  `Registry.PG` already does that. What it adds is cluster-wide *uniqueness*:
  `:pg` permits several pids to join one session group and returns whichever
  comes first, while Horde makes a registered name resolve to a single owning
  pid.

See each module's docs for wiring details.

## MCP authorization and metadata

The MCP authorization spec treats a protected HTTP MCP server as an OAuth
resource server. Clients discover authorization information through OAuth
Protected Resource Metadata (RFC 9728), then use Authorization Server Metadata
(RFC 8414) for issuer endpoints.

This package provides builders for:

- `/.well-known/oauth-protected-resource` metadata.
- `authorization_servers` handoff to one or more issuers.
- `issuer`, `jwks_uri`, `authorization_endpoint`, and `token_endpoint` metadata
  via Attesto's authorization-server metadata builder.
- Resource identifier handling through the explicit `:resource` value you pass.

It intentionally avoids a hard dependency on a specific Elixir MCP SDK. Anubis
gets a bridge because its frame authorization contract is widely used and small
to support; the core auth boundary remains a normal Plug boundary.

### How clients identify themselves

None of this is the resource server's concern — how a client obtains a token is
settled between it and the authorization server, and `attesto_mcp` only
validates what arrives. It matters when choosing what to enable on the
authorization server, so it is worth stating which way the spec has moved.

The MCP authorization spec now prefers **Client ID Metadata Documents** (CIMD):
the client uses an HTTPS URL as its `client_id`, and the authorization server
dereferences that URL to a JSON metadata document. There is no registration
request and no per-client state on the server. Dynamic client registration (RFC
7591) is deprecated in favour of it.

`attesto_phoenix` implements both. CIMD is off by default and enabled through
its `:client_id_metadata` configuration; the registration endpoint is likewise
opt-in. A CIMD client is always public (`none` + PKCE) or `private_key_jwt` — it
can never carry a shared secret — and installed applications are supported
through the document's own RFC 8252 §7.3 loopback redirect URIs.

The token this server validates is the same either way, so no `attesto_mcp`
wiring changes with that choice.

### Per-resource audience confinement (RFC 8707 + RFC 9728)

A protected resource advertises its own identifier as the RFC 9728 metadata
`resource`; a spec-correct client echoes that identifier back as the RFC 8707
`resource` parameter at the token endpoint, and the authorization server mints
the token's `aud` to it (see `attesto`/`attesto_phoenix`). The resource server's
job is the last link: validate that the presented token's `aud` is *this*
resource, so a token minted for a sibling endpoint cannot be replayed here.

`ProtectResource` / `Plug.Authenticate` enforce that with `resource_audience`:

```elixir
plug AttestoMCP.Plug.ProtectResource,
  config: &MyApp.Attesto.config/0,
  resource: "/mcp",
  base_url: "https://mcp.example.com",   # pin the origin behind a proxy
  resource_audience: :resource,          # validate aud == this resource's identifier
  scopes: [AttestoMCP.Scopes.tools_call()]
```

`resource_audience: :resource` validates the token's `aud` against this
endpoint's identifier (`base_url` + `resource` path) instead of the host's
global `config.audience`. A scalar audience must equal that identifier; for an
array-valued `aud`, every member must equal it, so a token cannot add a sibling
audience and remain valid. That identifier is computed by the same
`AttestoMCP.Metadata.resource_identifier/3` that produces the advertised
metadata `resource`, so the chain — `metadata.resource` == requested `resource`
== minted `aud` == validated `aud` — holds by construction. You can also pass a
literal string or a `(conn -> uri)` / `{m, f}` callback.

Audience callbacks must return a valid identifier. A `nil` or malformed result
fails authentication; it never disables route confinement for that request.

`resource_audience` and Attesto core's `trusted_audiences` option are mutually
exclusive. Choose the route-derived convenience option or supply the complete
core policy directly; configuring both raises during plug initialization so
neither policy can silently replace the other.

Pin the origin with `:base_url` when you enable this behind a TLS-terminating
proxy: the identifier is otherwise derived from the live request origin
(`Host` / forwarded headers), which an attacker could spoof to a sibling
resource's identifier. `resource_audience` is opt-in so existing single-audience
deployments are unaffected; enabling it (with a pinned origin) is the
recommended wiring for any server that fronts more than one MCP resource.

## What this package is not

`attesto_mcp` does not implement MCP, JSON-RPC, tools, prompts, resources,
transports, or server lifecycle. It wraps the HTTP endpoint your MCP server
implementation exposes and connects that endpoint to Attesto's OAuth/OIDC token
verification, DPoP proof verification, mTLS certificate binding, scope algebra,
and metadata builders.

`attesto` is the protocol engine: JWT access tokens, DPoP, mTLS, PKCE, JWKS,
discovery, and scopes. `attesto_mcp` reuses those checks and adds MCP-facing
Plug and Anubis ergonomics.

`attesto_phoenix` is the Phoenix/Ecto authorization-server layer: routes,
controllers, client registration and CIMD, stores, and Phoenix-friendly
configuration. MCP servers that need clients to identify themselves without
prior registration should expose CIMD — or, for the deprecated path, RFC 7591
registration — through the authorization server layer rather than duplicate
either here.

## Installation

```elixir
def deps do
  [
    {:attesto_mcp, "~> 1.0"}
  ]
end
```

For Phoenix apps, the optional Igniter installer can scaffold the protected
resource metadata route and protecting pipeline:

```bash
mix attesto_mcp.install --resource-path /mcp --scopes mcp:tools:call
```

The installer emits the public
`attesto_mcp_protected_resource_metadata/2` macro with `root: false` and
generates protection with the same path/scopes plus
`resource_audience: :resource`. Re-running the same resource is a no-op;
installing another resource adds another path-inserted metadata document but
never an ambiguous shared root. If a legacy client needs the unsuffixed root,
change exactly one declaration to `root: true` explicitly.

For a fuller Phoenix wiring example, see [the MCP wiring guide](guides/mcp_wiring.md).

## Minimal Plug/Phoenix usage

Protect the mounted MCP endpoint before forwarding to whichever MCP server plug
you use:

```elixir
pipeline :mcp_auth do
  plug AttestoMCP.Plug.Authenticate,
    config: &MyApp.Attesto.config/0,
    htu: fn _conn -> "https://mcp.example.com/mcp" end,
    replay_check: &MyApp.DPoPReplay.check_and_record/2,
    resource_path: "/mcp",
    principal: fn claims, sender ->
      MyApp.Principals.from_token(claims, sender)
    end

  plug AttestoMCP.Plug.RequireScopes,
    scopes: [AttestoMCP.Scopes.tools_call()]
end

scope "/" do
  pipe_through [:mcp_auth]
  forward "/mcp", to: MyApp.MCPServerPlug
end
```

`AttestoMCP.Plug.ProtectResource` composes the two plugs above —
authenticate, then require scopes — into one correctly-ordered, halt-respecting
plug, so a route declares both in a single line and both render through the same
error envelope and `resource_metadata` challenge:

```elixir
plug AttestoMCP.Plug.ProtectResource,
  config: &MyApp.Attesto.config/0,
  replay_check: &MyApp.DPoPReplay.check_and_record/2,
  resource: "/mcp",
  base_url: "https://mcp.example.com",
  resource_audience: :resource,
  scopes: [AttestoMCP.Scopes.tools_call()]
```

After authentication, downstream code can read:

- `conn.assigns.attesto_mcp_claims`
- `conn.assigns.attesto_mcp_scopes`
- `conn.assigns.attesto_mcp_sender`
- `conn.assigns.attesto_mcp_principal`, if `:principal` is configured
- `conn.assigns.attesto_context` - a neutral `%{subject, client_id, scope,
  claims, cnf, principal}` map, the same protocol context
  `AttestoPhoenix.Plug.Authenticate` assigns

For mTLS-bound access tokens, supply certificate context from your TLS layer:

```elixir
plug AttestoMCP.Plug.Authenticate,
  config: &MyApp.Attesto.config/0,
  cert_der: fn conn ->
    MyApp.TLS.client_certificate_der(conn)
  end
```

The callback must return the DER-encoded certificate that the TLS layer already
authenticated, or `nil` when no certificate was presented.

## Metadata

The installer mounts the standard metadata routes for a resource path. When
building metadata directly, serve protected-resource metadata from the
well-known location derived from your MCP resource identifier:

```elixir
metadata =
  AttestoMCP.Metadata.protected_resource(conn, "/mcp",
    authorization_servers: ["https://auth.example.com"],
    resource_name: "Example MCP server",
    scopes_supported: AttestoMCP.Scopes.all(),
    tls_client_certificate_bound_access_tokens: true
  )
```

Authorization-server metadata belongs at the issuer:

```elixir
AttestoMCP.Metadata.authorization_server(config,
  authorization_endpoint: "https://auth.example.com/oauth/authorize",
  token_endpoint_auth_methods_supported: ["client_secret_basic", "private_key_jwt"],
  registration_endpoint: "https://auth.example.com/oauth/register"
)
```

How discovery actually happens: a client hits the resource URL, gets a 401
whose `WWW-Authenticate` challenge carries a `resource_metadata` pointer
(RFC 9728 §5.1) — and modern MCP clients also (often first) derive the §3.1
**path-inserted** well-known URI from the resource URL itself
(`https://host.example/mcp` → `/.well-known/oauth-protected-resource/mcp`).
The path-inserted form must serve a document whose `resource` member equals the
identifier the URI was derived from (§3.3). A single-resource router can also
mount the unsuffixed compatibility document; a multi-resource router must
either omit it or assign it explicitly, never by declaration order. For a
combined AS+RS app that already mounts `attesto_phoenix`'s
`attesto_routes` (which serves the root document), give each PRM route exactly
one owner: single-resource hosts can use
`attesto_routes(protected_resource_paths: ["/mcp"])` instead of this macro,
and hosts using this macro alongside `attesto_routes` should pass `root:
false` here or `protected_resource_root: false` there.

For the complete combined-host pattern—one authorization-server route set,
class-specific OAuth pipelines, two MCP metadata declarations, matching
audience-confined protection, and both RFC 8707 allowed resource identifiers—
see [the MCP wiring guide](guides/mcp_wiring.md#combined-authorization-server-and-multiple-mcp-resources).

Client onboarding belongs to the authorization server, not here. With
`attesto_phoenix` that means enabling CIMD (`:client_id_metadata`) for the
preferred path, and its registration route and callbacks if you still need RFC
7591 — see [How clients identify themselves](#how-clients-identify-themselves).
Only advertise registration response fields such as `client_secret_expires_at`,
`registration_access_token`, and `registration_client_uri` if the authorization
server implementation returns and persists them correctly.

## Scope conventions

The package ships common MCP-style scope strings as conventions:

- `mcp:tools:read`
- `mcp:tools:call`
- `mcp:resources:read`
- `mcp:prompts:read`

Server-specific prefixes are available:

```elixir
AttestoMCP.Scopes.server("search", :tools_call)
# "search:mcp:tools:call"
```

These helpers are not policy. The authorization server decides what to issue and
each MCP route decides what to require.

## DPoP nonce and replay

DPoP proof replay protection is required for protected-resource requests. Pass a
shared `:replay_check` callback, such as an ETS store for a single node or a
database-backed store for clustered deployments. Without that callback, DPoP
requests fail closed through Attesto unless you explicitly acknowledge the risk
with Attesto's lower-level option.

If the server requires DPoP nonces, also pass `:nonce_check` and `:nonce_issue`.
Nonce failures produce `use_dpop_nonce` with a fresh `DPoP-Nonce` header so the
client can retry.

## Security notes

- Use HTTPS for HTTP MCP servers.
- Validate token audience/resource identifiers for the exact MCP endpoint. When
  one server fronts more than one resource, enable `resource_audience: :resource`
  with a pinned `:base_url` so a token minted for a sibling resource is rejected
  (see "Per-resource audience confinement" above).
- Do not accept access tokens in the URI query string.
- MCP auth defaults to `bearer_methods: [:header]`. Enable
  `bearer_methods: [:header, :body]` only if your metadata also advertises body
  credentials and you accept the logging, retry, and replay risks.
- Do not pass inbound MCP access tokens through to unrelated upstream services.
- Keep access tokens short-lived and scoped to the smallest MCP capability that
  can satisfy the request.
- Prefer DPoP or mTLS sender-constrained tokens for MCP servers exposed beyond a
  trusted local environment.

## Development

```bash
mix deps.get
mix format --check-formatted
mix credo --strict
mix test
mix docs
```

## License

MIT. See [LICENSE](LICENSE).
