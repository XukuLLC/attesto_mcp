# AttestoMCP

[![Hex.pm](https://img.shields.io/hexpm/v/attesto_mcp)](https://hex.pm/packages/attesto_mcp)
[![Hexdocs.pm](https://img.shields.io/badge/docs-hexdocs.pm-blue)](https://hexdocs.pm/attesto_mcp)
[![Elixir CI](https://github.com/XukuLLC/attesto_mcp/actions/workflows/elixir.yml/badge.svg)](https://github.com/XukuLLC/attesto_mcp/actions/workflows/elixir.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](https://github.com/XukuLLC/attesto_mcp/blob/main/LICENSE)
[![Elixir](https://img.shields.io/badge/elixir-%E2%89%A5%201.18-purple)](https://elixir-lang.org)

Plug/Phoenix helpers for protecting HTTP-based Model Context Protocol servers
with [attesto](https://hex.pm/packages/attesto).

## Where it fits

`attesto_mcp` is a narrow integration layer. It does not implement MCP, JSON-RPC,
tools, prompts, resources, transports, or server lifecycle. It wraps the HTTP
endpoint that an MCP server implementation exposes and connects that endpoint to
Attesto's OAuth/OIDC token verification, DPoP proof verification, mTLS
certificate binding, scope algebra, and metadata builders.

Use it when your MCP server is a Plug or Phoenix endpoint and you want:

- Bearer and DPoP authorization scheme handling.
- Rejection of DPoP-bound tokens that are presented as plain Bearer tokens.
- Rejection of mTLS-bound tokens unless the request has matching certificate
  thumbprint context.
- Verified claims, scopes, and sender context in `conn.assigns`.
- A host callback that maps verified token claims into your own principal.
- RFC 9728 protected-resource metadata for MCP OAuth discovery.
- OAuth-compatible errors with host-controlled rendering.

## Relationship to attesto and attesto_phoenix

`attesto` is the protocol engine: JWT access tokens, DPoP, mTLS, PKCE, JWKS,
discovery, and scopes. `attesto_mcp` reuses those checks and adds MCP-facing
Plug ergonomics.

`attesto_phoenix` is the Phoenix/Ecto authorization-server layer: routes,
controllers, registration, stores, and Phoenix-friendly configuration. MCP
servers that need dynamic client registration should expose it through the
authorization server layer rather than duplicate RFC 7591 here.

## MCP authorization

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

It intentionally avoids a hard dependency on a specific Elixir MCP SDK. Existing
packages have different license and maintenance profiles, and the auth boundary
is a normal Plug boundary.

## Installation

```elixir
def deps do
  [
    {:attesto_mcp, "~> 0.6"}
  ]
end
```

For Phoenix apps, the optional Igniter installer can scaffold the protected
resource metadata route and protecting pipeline:

```bash
mix attesto_mcp.install --resource-path /mcp --scopes mcp:tools:call
```

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
  scopes: [AttestoMCP.Scopes.tools_call()]
```

After authentication, downstream code can read:

- `conn.assigns.attesto_mcp_claims`
- `conn.assigns.attesto_mcp_scopes`
- `conn.assigns.attesto_mcp_sender`
- `conn.assigns.attesto_mcp_principal`, if `:principal` is configured
- `conn.assigns.attesto_context` - a neutral `%{subject, client_id, scope,
  claims, cnf, principal}` map, the same protocol-shaped context
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

Dynamic client registration should be exposed by the authorization server. When
using `attesto_phoenix`, enable its registration route and callbacks there. Only
advertise registration response fields such as `client_secret_expires_at`,
`registration_access_token`, and `registration_client_uri` if the authorization
server implementation returns and persists them correctly.

## Anubis servers

If your MCP server runs on [Anubis](https://hex.pm/packages/anubis_mcp), its
framework-level authorization (the `tools/list` visibility filter, per-tool scope
gates) reads identity from `frame.context.auth`, not `conn.assigns`.
`AttestoMCP.Anubis.put_auth/1` projects the verified `:attesto_context` into that
field — call it once at the top of `handle_request/2`:

```elixir
def handle_request(request, frame) do
  frame = AttestoMCP.Anubis.put_auth(frame)
  # Anubis authorization now sees the verified subject/scopes/claims.
end
```

`anubis_mcp` is an optional dependency: the bridge module compiles only when
Anubis is present, so a non-Anubis resource server pays nothing for it. The
projection is purely mechanical — no scope-superset, role, or visibility policy,
which stay in your app.

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
- Validate token audience/resource identifiers for the exact MCP endpoint.
- Do not accept access tokens in the URI query string.
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
