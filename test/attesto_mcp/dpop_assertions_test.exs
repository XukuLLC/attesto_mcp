defmodule AttestoMCP.Test.DPoPAssertionsTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import AttestoMCP.Test.DPoPAssertions

  alias AttestoMCP.Plug.ProtectResource
  alias AttestoMCP.Scopes
  alias AttestoMCP.Test.DPoPReplay
  alias AttestoMCP.Test.Factory

  setup do
    %{config: Factory.config()}
  end

  test "rejects a DPoP-bound token presented as a plain Bearer", %{config: config} do
    conn = assert_dpop_bound_bearer_rejected(protect_fun(config), config, scopes: [Scopes.tools_call()])

    assert conn.status == 401
    assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
  end

  test "accepts a DPoP-bound token presented with a valid proof", %{config: config} do
    conn = assert_dpop_proof_accepted(protect_fun(config), config, scopes: [Scopes.tools_call()])

    assert conn.assigns.attesto_mcp_sender.binding == :dpop
  end

  defp protect_fun(config) do
    opts =
      ProtectResource.init(
        config: config,
        htu: &Factory.htu/1,
        replay_check: DPoPReplay.callback(),
        scopes: [Scopes.tools_call()]
      )

    fn conn -> ProtectResource.call(conn, opts) end
  end
end
