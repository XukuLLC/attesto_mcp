defmodule AttestoMCP.MetadataTest do
  @moduledoc false
  use ExUnit.Case, async: true

  import Plug.Test

  alias AttestoMCP.Metadata
  alias AttestoMCP.Scopes
  alias AttestoMCP.Test.Factory

  test "protected resource metadata includes MCP OAuth handoff fields" do
    metadata =
      Metadata.protected_resource(
        resource: "https://mcp.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        resource_name: "Example MCP server",
        tls_client_certificate_bound_access_tokens: true
      )

    assert metadata["resource"] == "https://mcp.example.com/mcp"
    assert metadata["authorization_servers"] == ["https://auth.example.com"]
    assert Scopes.tools_call() in metadata["scopes_supported"]
    assert metadata["bearer_methods_supported"] == ["header"]
    assert metadata["tls_client_certificate_bound_access_tokens"] == true
  end

  test "protected resource metadata can be derived from a Plug connection" do
    conn = conn(:get, "https://mcp.example.com/.well-known/oauth-protected-resource/mcp/user")

    metadata =
      Metadata.protected_resource(conn, "/mcp/user", scopes_supported: ["mcp:user"])

    assert metadata["resource"] == "https://mcp.example.com/mcp/user"
    assert metadata["authorization_servers"] == ["https://mcp.example.com"]
    assert metadata["scopes_supported"] == ["mcp:user"]
  end

  test "protected resource URL can be derived from a Plug connection" do
    conn = conn(:get, "https://mcp.example.com/mcp/user")

    assert Metadata.protected_resource_url(conn, "/mcp/user") ==
             "https://mcp.example.com/.well-known/oauth-protected-resource/mcp/user"
  end

  test "an explicit :base_url pins the resource origin over the request connection" do
    # Behind a TLS-terminating proxy the conn is http + an internal host; the
    # pinned origin must win so the advertised resource is correct/non-spoofable.
    conn = conn(:get, "http://10.0.0.5/.well-known/oauth-protected-resource/mcp")

    metadata = Metadata.protected_resource(conn, "/mcp", base_url: "https://mcp.example.com")

    assert metadata["resource"] == "https://mcp.example.com/mcp"
  end

  test ":origin accepts a (conn -> url) callback resolved at request time" do
    conn = conn(:get, "http://10.0.0.5/.well-known/oauth-protected-resource/mcp")

    metadata = Metadata.protected_resource(conn, "/mcp", origin: fn _conn -> "https://mcp.example.com" end)

    assert metadata["resource"] == "https://mcp.example.com/mcp"
  end

  test "authorization_servers defaults to the :config issuer, not the resource origin" do
    conn = conn(:get, "https://mcp.example.com/.well-known/oauth-protected-resource/mcp")

    metadata = Metadata.protected_resource(conn, "/mcp", config: Factory.config())

    # The resource is the resource server's own origin; the AS is the issuer.
    assert metadata["resource"] == "https://mcp.example.com/mcp"
    assert metadata["authorization_servers"] == ["https://auth.example.com"]
  end

  test "an explicit :issuer string sets authorization_servers verbatim (issuer is matched exactly)" do
    conn = conn(:get, "https://mcp.example.com/.well-known/oauth-protected-resource/mcp")

    # An issuer identifier is compared by exact string match, so a trailing slash
    # MUST be preserved - unlike the resource origin, which is trimmed.
    metadata = Metadata.protected_resource(conn, "/mcp", issuer: "https://auth.example.com/tenant/")

    assert metadata["authorization_servers"] == ["https://auth.example.com/tenant/"]
  end

  test "a blank :issuer is ignored and falls through to the :config issuer" do
    conn = conn(:get, "https://mcp.example.com/.well-known/oauth-protected-resource/mcp")

    metadata = Metadata.protected_resource(conn, "/mcp", issuer: "", config: Factory.config())

    assert metadata["authorization_servers"] == ["https://auth.example.com"]
  end

  test "an explicit :resource overrides the derived identifier" do
    conn = conn(:get, "https://mcp.example.com/.well-known/oauth-protected-resource/mcp")

    metadata = Metadata.protected_resource(conn, "/mcp", resource: "https://canonical.example/mcp")

    assert metadata["resource"] == "https://canonical.example/mcp"
  end

  test "protected_resource_url/3 pins the origin via :base_url" do
    conn = conn(:get, "http://10.0.0.5/mcp")

    assert Metadata.protected_resource_url(conn, "/mcp", base_url: "https://mcp.example.com") ==
             "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
  end

  test "resolve_origin/2 falls back to the request origin and trims a pinned trailing slash" do
    conn = conn(:get, "https://mcp.example.com/x")

    assert Metadata.resolve_origin(conn, []) == "https://mcp.example.com"
    assert Metadata.resolve_origin(conn, base_url: "https://canonical.example/") == "https://canonical.example"
  end

  test ":base_url accepts an {module, fun} tuple resolved at request time" do
    conn = conn(:get, "http://10.0.0.5/.well-known/oauth-protected-resource/mcp")

    metadata = Metadata.protected_resource(conn, "/mcp", base_url: {__MODULE__, :pinned_origin})

    assert metadata["resource"] == "https://mcp.example.com/mcp"
  end

  def pinned_origin(_conn), do: "https://mcp.example.com"

  test "a blank :base_url is treated as not-configured and falls back to :origin then the request" do
    conn = conn(:get, "https://request-host.example/.well-known/oauth-protected-resource/mcp")

    # Blank base_url must not produce relative/empty metadata; it yields to :origin.
    via_origin = Metadata.protected_resource(conn, "/mcp", base_url: "", origin: "https://canonical.example")
    assert via_origin["resource"] == "https://canonical.example/mcp"

    # With nothing usable pinned, it fails back to the request origin.
    via_request = Metadata.protected_resource(conn, "/mcp", base_url: "")
    assert via_request["resource"] == "https://request-host.example/mcp"
  end

  test "a slash-only or relative :base_url is rejected, never producing relative/empty metadata" do
    conn = conn(:get, "https://request-host.example/.well-known/oauth-protected-resource/mcp")

    bad_pins = [
      "/",
      "///",
      "/prefix",
      "mcp.example.com",
      "",
      "://x",
      "https:///path",
      "ftp://x",
      "https://",
      "https://user:pass@host",
      "https://host?x=1",
      "https://host#frag"
    ]

    for bad <- bad_pins do
      metadata = Metadata.protected_resource(conn, "/mcp", base_url: bad)
      assert metadata["resource"] == "https://request-host.example/mcp", "rejected pin #{inspect(bad)}"
      assert metadata["authorization_servers"] == ["https://request-host.example"]
    end

    # A slash-only base_url yields to a valid :origin rather than the request.
    via_origin = Metadata.protected_resource(conn, "/mcp", base_url: "/", origin: "https://canonical.example")
    assert via_origin["resource"] == "https://canonical.example/mcp"

    # A port and a path prefix (path-prefix proxy) are legitimate and accepted.
    with_port = Metadata.protected_resource(conn, "/mcp", base_url: "http://mcp.example.com:4000/base")
    assert with_port["resource"] == "http://mcp.example.com:4000/base/mcp"
  end

  test "the resource origin is resolved once and shared with the authorization_servers fallback" do
    conn = conn(:get, "https://request-host.example/.well-known/oauth-protected-resource/mcp")
    {:ok, counter} = Agent.start_link(fn -> 0 end)

    origin = fn _conn ->
      Agent.update(counter, &(&1 + 1))
      "https://pinned.example"
    end

    metadata = Metadata.protected_resource(conn, "/mcp", base_url: origin)

    # resource and the authorization_servers fallback share one resolved origin...
    assert metadata["resource"] == "https://pinned.example/mcp"
    assert metadata["authorization_servers"] == ["https://pinned.example"]
    # ...and the (stateful) callback ran exactly once for the whole document.
    assert Agent.get(counter, & &1) == 1
  end

  test "a :config issuer with a trailing slash is advertised verbatim" do
    conn = conn(:get, "https://mcp.example.com/.well-known/oauth-protected-resource/mcp")
    config = %{Factory.config() | issuer: "https://auth.example.com/tenant/"}

    metadata = Metadata.protected_resource(conn, "/mcp", config: config)

    assert metadata["authorization_servers"] == ["https://auth.example.com/tenant/"]
  end

  test "an explicit :resource / :authorization_servers short-circuits lower-precedence callbacks" do
    conn = conn(:get, "https://mcp.example.com/.well-known/oauth-protected-resource/mcp")

    # Both values are supplied outright, so the origin and config callbacks - which
    # would raise - must never be invoked.
    metadata =
      Metadata.protected_resource(conn, "/mcp",
        resource: "https://canonical.example/mcp",
        authorization_servers: ["https://auth.example.com"],
        base_url: fn _conn -> raise "origin callback should not run" end,
        config: fn -> raise "config callback should not run" end
      )

    assert metadata["resource"] == "https://canonical.example/mcp"
    assert metadata["authorization_servers"] == ["https://auth.example.com"]
  end

  test "authorization server metadata delegates to Attesto discovery" do
    metadata =
      Factory.config()
      |> Metadata.authorization_server(
        authorization_endpoint: "https://auth.example.com/oauth/authorize",
        registration_endpoint: "https://auth.example.com/oauth/register"
      )

    assert metadata["issuer"] == "https://auth.example.com"
    assert metadata["authorization_endpoint"] == "https://auth.example.com/oauth/authorize"
    assert metadata["registration_endpoint"] == "https://auth.example.com/oauth/register"
  end
end
