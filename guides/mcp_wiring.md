# Wiring an MCP server

This guide shows the canonical end-to-end wiring for protecting an HTTP MCP
server with `attesto_mcp`: mount the metadata discovery routes, protect the MCP
endpoint with one plug, and require the scopes the endpoint needs. Every step is
copy-pasteable.

The pieces fit together so that the RFC 9728 `resource` identifier a client
discovers and the `resource_metadata` challenge the server returns on a 401
always agree, because both derive from the same request origin and resource
path.

## 1. Attesto config

`attesto_mcp` delegates token, DPoP, and mTLS verification to Attesto, so the
host supplies an `Attesto.Config` (or a zero-arity function returning one).

```elixir
defmodule MyApp.Attesto do
  def config do
    Attesto.Config.new(
      issuer: "https://auth.example.com",
      audience: "https://mcp.example.com/mcp",
      keystore: MyApp.Attesto.Keystore
    )
  end
end
```

## 2. DPoP replay protection

DPoP proof replay protection is required for protected-resource requests. Wire a
shared `:replay_check` callback (an ETS store for a single node, a
database-backed store for a cluster). Without it, DPoP requests fail closed
through Attesto.

```elixir
replay_check = &MyApp.DPoPReplay.check_and_record/2
```

## 3. Mount discovery routes

`use AttestoMCP.Router` adds `attesto_mcp_protected_resource_metadata/2`, which
serves `/.well-known/oauth-protected-resource/<path>` for each resource. For a
single resource it also serves a backwards-compatible root
`/.well-known/oauth-protected-resource` by default.

```elixir
defmodule MyAppWeb.Router do
  use Phoenix.Router
  use AttestoMCP.Router

  pipeline :api do
    plug :accepts, ["json"]
  end

  scope "/" do
    pipe_through :api

    attesto_mcp_protected_resource_metadata "/mcp",
      scopes: [AttestoMCP.Scopes.tools_call()],
      base_url: "https://mcp.example.com"
  end

  # ... protected endpoint below
end
```

Serving more than one MCP server is one call per resource. Each gets its own
metadata document and scope list. A shared root cannot identify all of them, so
the macro never assigns it by declaration order: a second implicit resource is
a compile-time error. Either serve no root document:

```elixir
attesto_mcp_protected_resource_metadata "/mcp/foo",
  scopes: ["foo:mcp:tools:call"],
  root: false

attesto_mcp_protected_resource_metadata "/mcp/bar",
  scopes: ["bar:mcp:tools:call"],
  root: false
```

Or explicitly nominate exactly one resource for legacy root discovery:

```elixir
attesto_mcp_protected_resource_metadata "/mcp/foo",
  scopes: ["foo:mcp:tools:call"],
  root: false

attesto_mcp_protected_resource_metadata "/mcp/bar",
  scopes: ["bar:mcp:tools:call"],
  root: true
```

`mix attesto_mcp.install` uses `root: false`, so sequential installations are
safe by default. Change one declaration to `root: true` only when a legacy
client requires the unsuffixed document.

## 4. Protect the endpoint with one plug

`AttestoMCP.Plug.ProtectResource` composes authentication and scope enforcement
into one correctly ordered, halt-respecting plug. The `:resource` it is given is
the same path mounted for discovery above, so the `resource_metadata` challenge
on a 401 points at the route from step 3.

```elixir
pipeline :mcp do
  plug :accepts, ["json", "sse"]

  plug AttestoMCP.Plug.ProtectResource,
    config: &MyApp.Attesto.config/0,
    replay_check: &MyApp.DPoPReplay.check_and_record/2,
    resource: "/mcp",
    base_url: "https://mcp.example.com",
    resource_audience: :resource,
    scopes: [AttestoMCP.Scopes.tools_call()],
    principal: fn claims, sender ->
      MyApp.Principals.from_token(claims, sender)
    end
end

scope "/" do
  pipe_through :mcp

  forward "/mcp", MyApp.MCPServerPlug
end
```

The metadata declaration and protection pipeline must use the same resource
path, scopes, and origin. `resource_audience: :resource` makes that identifier
the token audience check, so a sibling resource cannot accept the token merely
because it requires the same scope. When `:base_url`/`:origin` is omitted, both
sides derive the origin from the request; pin the same value on both behind a
reverse proxy.

## Combined authorization server and multiple MCP resources

One Phoenix host can mount one `attesto_phoenix` authorization-server catalog
and one protected-resource metadata declaration per MCP endpoint. Keep MCP
metadata in `attesto_mcp`, suppress the authorization server's root PRM route,
and make the browser-facing pipeline override explicit:

```elixir
scope "/" do
  attesto_routes(
    prefix: "/mcp",
    pipeline: :oauth_common,
    route_pipelines: [
      interactive: [:oauth_interactive, :oauth_common]
    ],
    registration: true,
    protected_resource_root: false
  )

  attesto_mcp_protected_resource_metadata "/mcp/alpha",
    scopes: ["alpha:tools"],
    base_url: "https://mcp.example.com",
    root: false

  attesto_mcp_protected_resource_metadata "/mcp/beta",
    scopes: ["beta:tools"],
    base_url: "https://mcp.example.com",
    root: false
end
```

Protect the resources with matching paths, origins, and scope lists:

```elixir
pipeline :mcp_alpha do
  plug :accepts, ["json", "sse"]

  plug AttestoMCP.Plug.ProtectResource,
    config: &MyApp.Attesto.resource_config/0,
    resource: "/mcp/alpha",
    scopes: ["alpha:tools"],
    base_url: "https://mcp.example.com",
    resource_audience: :resource
end

pipeline :mcp_beta do
  plug :accepts, ["json", "sse"]

  plug AttestoMCP.Plug.ProtectResource,
    config: &MyApp.Attesto.resource_config/0,
    resource: "/mcp/beta",
    scopes: ["beta:tools"],
    base_url: "https://mcp.example.com",
    resource_audience: :resource
end
```

The authorization-server configuration must allow both exact identifiers so
clients can send them as RFC 8707 `resource` parameters and receive confined
access-token audiences:

```elixir
resource_indicators: [
  allowed_resources: [
    "https://mcp.example.com/mcp/alpha",
    "https://mcp.example.com/mcp/beta"
  ]
]
```

The resulting chain is exact for each endpoint:
`metadata.resource == requested resource == token aud == validated audience`.
The host still owns its session/resource-owner authentication, CSRF, and
content-negotiation policy; externally submitted OAuth protocol POSTs should
not inherit generic browser-only handling.

After authentication, downstream code can read:

- `conn.assigns.attesto_mcp_claims`
- `conn.assigns.attesto_mcp_scopes`
- `conn.assigns.attesto_mcp_sender`
- `conn.assigns.attesto_mcp_principal`, if `:principal` is configured

## 5. mTLS-bound tokens (optional)

For mTLS sender-constrained tokens, supply certificate context from the TLS
layer. The callback returns the DER-encoded certificate the TLS layer already
authenticated, or `nil` when none was presented.

```elixir
plug AttestoMCP.Plug.ProtectResource,
  config: &MyApp.Attesto.config/0,
  resource: "/mcp",
  scopes: [AttestoMCP.Scopes.tools_call()],
  cert_der: fn conn -> MyApp.TLS.client_certificate_der(conn) end
```

## 6. Test the binding contract

`AttestoMCP.Test.DPoPAssertions` ships ExUnit assertions that drive your wired
pipeline and prove DPoP binding holds: a DPoP-bound token presented as a plain
Bearer is rejected, and the same token presented with a valid proof is accepted.

```elixir
defmodule MyAppWeb.MCPAuthTest do
  use ExUnit.Case
  import AttestoMCP.Test.DPoPAssertions

  setup do
    %{config: AttestoMCP.Test.Factory.config()}
  end

  test "the MCP pipeline enforces DPoP binding", %{config: config} do
    plug = fn conn ->
      opts =
        AttestoMCP.Plug.ProtectResource.init(
          config: config,
          replay_check: AttestoMCP.Test.DPoPReplay.callback(),
          scopes: [AttestoMCP.Scopes.tools_call()]
        )

      AttestoMCP.Plug.ProtectResource.call(conn, opts)
    end

    assert_dpop_bound_bearer_rejected(plug, config, scopes: [AttestoMCP.Scopes.tools_call()])
    assert_dpop_proof_accepted(plug, config, scopes: [AttestoMCP.Scopes.tools_call()])
  end
end
```
