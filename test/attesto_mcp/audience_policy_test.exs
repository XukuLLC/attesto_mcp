defmodule AttestoMCP.AudiencePolicyTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias AttestoMCP.Plug.Authenticate
  alias AttestoMCP.Plug.ProtectResource
  alias AttestoMCP.Scopes
  alias AttestoMCP.Telemetry
  alias AttestoMCP.Test.Factory

  @boundaries [:authenticate, :static, :prepared]
  @resource "https://mcp.example.com/mcp/tenant-a"
  @sibling "https://mcp.example.com/mcp/tenant-b"

  setup do
    %{config: Factory.config()}
  end

  test "every boundary requires a decision even with core audience and canonical metadata", %{config: config} do
    metadata_opts = [base_url: "https://mcp.example.com", resource_path: "/mcp/tenant-a"]

    for boundary <- @boundaries,
        policy <- [[], [resource_audience: nil], [resource_audience: false]],
        discovery <- [[], metadata_opts, [resource_metadata_url: @resource <> "/metadata"]] do
      assert_raise ArgumentError, ~r/configure :resource_audience or :trusted_audiences explicitly/, fn ->
        initialize(boundary, config, policy ++ discovery)
      end
    end
  end

  test "missing policy is refused without resolving config at boot" do
    for boundary <- @boundaries do
      assert_raise ArgumentError, ~r/configure :resource_audience or :trusted_audiences explicitly/, fn ->
        initialize(boundary, fn -> flunk("config must stay lazy") end, [])
      end
    end
  end

  test "malformed explicit trust policies fail at initialization", %{config: config} do
    invalid = [
      nil,
      false,
      true,
      [],
      "audience",
      [""],
      [nil],
      [@resource, 42],
      fn -> [@resource] end,
      {__MODULE__, :trusted}
    ]

    for boundary <- @boundaries, trusted <- invalid do
      assert_raise ArgumentError, ~r/:trusted_audiences must be/, fn ->
        initialize(boundary, config, trusted_audiences: trusted)
      end
    end
  end

  test "active resource and core policies cannot silently replace one another", %{config: config} do
    for boundary <- @boundaries, trusted <- [[@sibling], nil, false] do
      assert_raise ArgumentError, ~r/mutually exclusive/, fn ->
        initialize(boundary, config, resource_audience: @resource, trusted_audiences: trusted)
      end
    end
  end

  test "resource derivation requires a path and trusted origin on every boundary", %{config: config} do
    for boundary <- @boundaries do
      assert_raise ArgumentError, ~r/requires a :resource \/ :resource_path option/, fn ->
        initialize(boundary, config, resource_audience: :resource)
      end

      assert_raise ArgumentError, ~r/requires a pinned :base_url or :origin/, fn ->
        initialize(boundary, config, resource_audience: :resource, resource_path: "/mcp")
      end
    end
  end

  test "explicit policies accept their resource and reject sibling, mixed and global audiences", %{config: config} do
    policies = [
      [resource_audience: @resource],
      [resource_audience: :resource, resource_path: "/mcp/tenant-a", origin: {__MODULE__, :origin}],
      [trusted_audiences: [@resource]],
      [trusted_audiences: &__MODULE__.trusted/1],
      [resource_audience: false, trusted_audiences: [@resource]],
      [resource_audience: nil, trusted_audiences: [@resource]]
    ]

    tokens =
      for audience <- [@resource, @sibling, [@resource, @sibling], config.audience] do
        {audience, Factory.access_token(config, audience: audience)}
      end

    for boundary <- @boundaries, policy <- policies do
      protection = initialize(boundary, config, policy)

      for {audience, token} <- tokens do
        # Neither an attacker Host nor the global core audience selects trust.
        result = run(boundary, protection, token)

        if audience == @resource do
          refute result.halted
          assert result.assigns.attesto_mcp_claims["aud"] == @resource
        else
          assert result.halted
          assert result.status == 401
          assert Telemetry.outcome(result) == :invalid_audience
          assert JSON.decode!(result.resp_body)["error"] == "invalid_token"
        end
      end
    end
  end

  test "an explicit trust list can deliberately accept multiple identifiers", %{config: config} do
    token = Factory.access_token(config, audience: [@resource, @sibling])

    for boundary <- @boundaries do
      protection = initialize(boundary, config, trusted_audiences: [@resource, @sibling])
      refute run(boundary, protection, token).halted
    end
  end

  test "trusted audience resolvers stay lazy and malformed results fail closed", %{config: config} do
    token = Factory.access_token(config)

    for boundary <- @boundaries, result <- [nil, false, [], [""], [config.audience, nil]] do
      resolver = fn claims ->
        assert claims["iss"] == config.issuer
        send(self(), :resolved)
        result
      end

      protection = initialize(boundary, config, trusted_audiences: resolver)
      refute_received :resolved
      response = run(boundary, protection, token)
      assert_received :resolved
      assert response.status == 401
      assert Telemetry.outcome(response) == :invalid_audience
      assert JSON.decode!(response.resp_body)["error"] == "invalid_token"
    end

    for boundary <- @boundaries do
      protection = initialize(boundary, config, trusted_audiences: fn _ -> raise "resolver unavailable" end)
      assert run(boundary, protection, token).status == 401
    end
  end

  test "explicit resolver policies remain compile-safe" do
    for boundary <- @boundaries do
      assert boundary
             |> initialize(&Factory.config/0, trusted_audiences: &__MODULE__.trusted/1)
             |> Macro.escape()
    end
  end

  test "the shipped factory uses a fixed audience unless a test explicitly selects another", %{config: config} do
    other_config = %{config | audience: @sibling}
    token = Factory.access_token(other_config)
    request = conn(:post, @sibling) |> put_req_header("authorization", "Bearer " <> token)

    refused = Factory.authenticate(request, other_config)
    assert refused.status == 401
    assert Telemetry.outcome(refused) == :invalid_audience

    refute Factory.authenticate(request, other_config, trusted_audiences: [@sibling]).halted
    refute Factory.authenticate(request, other_config, resource_audience: @sibling).halted

    assert_raise ArgumentError, ~r/configure :resource_audience or :trusted_audiences explicitly/, fn ->
      Factory.authenticate(request, other_config, resource_audience: false)
    end
  end

  test "compile-time plug pipelines fail without a policy" do
    for plug <- [Authenticate, ProtectResource] do
      module = Module.concat(__MODULE__, "MissingPolicy#{System.unique_integer([:positive])}")

      assert_raise ArgumentError, ~r/configure :resource_audience or :trusted_audiences explicitly/, fn ->
        Code.compile_string("""
        defmodule #{inspect(module)} do
          use Plug.Builder, init_mode: :compile
          plug #{inspect(plug)},
            config: &AttestoMCP.Test.Factory.config/0,
            resource_path: "/mcp",
            base_url: "https://mcp.example.com",
            scopes: ["mcp:tools:call"]
        end
        """)
      end
    end
  end

  def origin(_conn), do: "https://mcp.example.com"
  def trusted(%{"client_id" => "client-1"}), do: [@resource]

  defp initialize(:authenticate, config, opts), do: Authenticate.init([config: config] ++ opts)

  defp initialize(:static, config, opts),
    do: ProtectResource.init([config: config, scopes: [Scopes.tools_call()]] ++ opts)

  defp initialize(:prepared, config, opts), do: ProtectResource.prepare([config: config] ++ opts)

  defp run(boundary, protection, token) do
    request =
      :post
      |> conn("https://attacker.example/mcp/tenant-a")
      |> put_req_header("authorization", "Bearer " <> token)

    case boundary do
      :authenticate -> Authenticate.call(request, protection)
      :static -> ProtectResource.call(request, protection)
      :prepared -> request |> ProtectResource.authenticate(protection) |> ProtectResource.authorize(protection, [])
    end
  end
end
