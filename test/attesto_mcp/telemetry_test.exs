defmodule AttestoMCP.TelemetryTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias AttestoMCP.Plug.ProtectResource
  alias AttestoMCP.Plug.RequireScopes
  alias AttestoMCP.Scopes
  alias AttestoMCP.Telemetry
  alias AttestoMCP.Test.DPoPReplay
  alias AttestoMCP.Test.Factory

  @events for name <- [:authenticate, :require_scopes],
              stage <- [:start, :stop, :exception],
              do: [:attesto_mcp, name, stage]

  @allowed_metadata MapSet.new([:telemetry_span_context, :outcome, :status, :binding, :kind])

  setup do
    handler_id = {__MODULE__, make_ref()}
    :ok = :telemetry.attach_many(handler_id, @events, &__MODULE__.handle_event/4, self())
    on_exit(fn -> :telemetry.detach(handler_id) end)
    %{config: Factory.config()}
  end

  def handle_event(event, measurements, metadata, owner) do
    send(owner, {:telemetry, event, measurements, metadata})
  end

  defp bearer(token) do
    :post
    |> conn("/mcp")
    |> put_req_header("authorization", "Bearer " <> token)
  end

  defp assert_span(name, expected) do
    assert_receive {:telemetry, [:attesto_mcp, ^name, :start], start_measurements, start_metadata}
    assert is_integer(start_measurements.system_time)
    assert is_integer(start_measurements.monotonic_time)
    assert is_reference(start_metadata.telemetry_span_context)

    assert_receive {:telemetry, [:attesto_mcp, ^name, :stop], stop_measurements, stop_metadata}
    assert is_integer(stop_measurements.duration) and stop_measurements.duration >= 0
    assert stop_metadata.telemetry_span_context == start_metadata.telemetry_span_context
    assert MapSet.subset?(MapSet.new(Map.keys(stop_metadata)), @allowed_metadata)
    assert Map.take(stop_metadata, Map.keys(expected)) == expected
    stop_metadata
  end

  defp refute_span_leaks(metadata) do
    for key <- [:token, :claims, :principal, :scopes, :error_description, :reason, :description] do
      refute Map.has_key?(metadata, key)
    end
  end

  defp mint(config, opts) do
    principal = %{
      claims: %{"client_id" => "client-1"},
      kind: "user",
      scopes: [Scopes.tools_call()],
      sub: "usr_123"
    }

    {:ok, token} = Attesto.Token.mint(config, principal, opts)
    token.access_token
  end

  describe "[:attesto_mcp, :authenticate]" do
    test "an authenticated bearer request stops with :ok and its binding", %{config: config} do
      conn = config |> Factory.access_token() |> bearer() |> Factory.authenticate(config)

      refute conn.halted
      assert Telemetry.outcome(conn) == :ok
      metadata = assert_span(:authenticate, %{outcome: :ok, status: nil, binding: :bearer})
      refute_span_leaks(metadata)
    end

    test "an authenticated DPoP request reports the :dpop binding", %{config: config} do
      jwk = Factory.dpop_jwk()
      jkt = Factory.dpop_jkt(jwk)
      token = Factory.access_token(config, dpop_jkt: jkt)
      {proof, ^jkt} = Factory.dpop_proof(token, jwk: jwk)

      conn =
        :post
        |> conn("/mcp")
        |> put_req_header("authorization", "DPoP " <> token)
        |> put_req_header("dpop", proof)
        |> Factory.authenticate(config, replay_check: DPoPReplay.callback())

      refute conn.halted
      assert_span(:authenticate, %{outcome: :ok, binding: :dpop})
    end

    test "a request without credentials is :missing_credentials", %{config: config} do
      conn = :post |> conn("/mcp") |> Factory.authenticate(config)

      assert conn.halted
      assert Telemetry.outcome(conn) == :missing_credentials
      assert_span(:authenticate, %{outcome: :missing_credentials, status: 401, binding: nil})
    end

    test "an expired or not-yet-valid token is counted apart from other failures", %{config: config} do
      now = System.os_time(:second)

      expired = config |> mint(now: now - 86_400) |> bearer() |> Factory.authenticate(config)
      assert expired.status == 401
      assert_span(:authenticate, %{outcome: :token_expired, status: 401})

      early = config |> mint(now: now + 86_400) |> bearer() |> Factory.authenticate(config)
      assert early.status == 401
      assert_span(:authenticate, %{outcome: :token_not_yet_valid, status: 401})
    end

    test "a token for another resource is :invalid_audience", %{config: config} do
      conn =
        config
        |> Factory.access_token(audience: "https://other.example/api")
        |> bearer()
        |> Factory.authenticate(config)

      assert conn.status == 401
      assert_span(:authenticate, %{outcome: :invalid_audience, status: 401})
    end

    test "a garbled token is :invalid_token", %{config: config} do
      conn = "not.a.jwt" |> bearer() |> Factory.authenticate(config)

      assert conn.status == 401
      assert_span(:authenticate, %{outcome: :invalid_token, status: 401})
    end

    test "a DPoP-bound token presented as Bearer is :sender_constraint_mismatch", %{config: config} do
      jkt = Factory.dpop_jkt(Factory.dpop_jwk())
      conn = config |> Factory.access_token(dpop_jkt: jkt) |> bearer() |> Factory.authenticate(config)

      assert conn.status == 401
      assert_span(:authenticate, %{outcome: :sender_constraint_mismatch, status: 401})
    end

    test "a replayed DPoP proof is :dpop_replay and a bad proof :invalid_dpop_proof", %{config: config} do
      jwk = Factory.dpop_jwk()
      jkt = Factory.dpop_jkt(jwk)
      token = Factory.access_token(config, dpop_jkt: jkt)
      {proof, ^jkt} = Factory.dpop_proof(token, jwk: jwk)

      request =
        :post
        |> conn("/mcp")
        |> put_req_header("authorization", "DPoP " <> token)

      replayed =
        request
        |> put_req_header("dpop", proof)
        |> Factory.authenticate(config, replay_check: fn _jti, _ttl -> {:error, :replay} end)

      assert replayed.status == 401
      assert_span(:authenticate, %{outcome: :dpop_replay, status: 401})

      malformed =
        request
        |> put_req_header("dpop", "garbage")
        |> Factory.authenticate(config, replay_check: DPoPReplay.callback())

      assert malformed.status == 401
      assert_span(:authenticate, %{outcome: :invalid_dpop_proof, status: 401})
    end

    test "a nonce demand is :dpop_nonce_required", %{config: config} do
      jwk = Factory.dpop_jwk()
      jkt = Factory.dpop_jkt(jwk)
      token = Factory.access_token(config, dpop_jkt: jkt)
      {proof, ^jkt} = Factory.dpop_proof(token, jwk: jwk)

      conn =
        :post
        |> conn("/mcp")
        |> put_req_header("authorization", "DPoP " <> token)
        |> put_req_header("dpop", proof)
        |> Factory.authenticate(config,
          replay_check: DPoPReplay.callback(),
          nonce_check: fn _nonce -> {:error, :use_dpop_nonce} end,
          nonce_issue: fn -> "fresh-nonce" end
        )

      assert conn.status == 401
      assert ["fresh-nonce"] = get_resp_header(conn, "dpop-nonce")
      assert_span(:authenticate, %{outcome: :dpop_nonce_required, status: 401})
    end

    test "an unmet step-up requirement is :step_up_required", %{config: config} do
      conn =
        config
        |> Factory.access_token()
        |> bearer()
        |> Factory.authenticate(config, step_up: [acr_values: ["phr"]])

      assert conn.status == 401
      assert_span(:authenticate, %{outcome: :step_up_required, status: 401})
    end

    test "a principal callback refusal is :policy_rejected", %{config: config} do
      conn =
        config
        |> Factory.access_token()
        |> bearer()
        |> Factory.authenticate(config, principal: fn _claims, _sender -> {:error, :revoked} end)

      assert conn.status == 401
      assert JSON.decode!(conn.resp_body) == %{"error" => "invalid_token"}
      assert_span(:authenticate, %{outcome: :policy_rejected, status: 401, binding: nil})
    end

    test "a verifier outage is :verifier_unavailable", %{config: config} do
      conn =
        config
        |> Factory.access_token()
        |> bearer()
        |> Factory.authenticate(config,
          verify: fn _config, _token, _opts -> {:error, {:temporarily_unavailable, :jwks}} end
        )

      assert conn.status == 503
      assert_span(:authenticate, %{outcome: :verifier_unavailable, status: 503})
    end

    test "a host :send_error hook still renders the refusal and the outcome is recorded", %{config: config} do
      conn =
        :post
        |> conn("/mcp")
        |> Factory.authenticate(config,
          send_error: fn conn, status, body ->
            conn |> put_resp_header("x-rendered-by", "host") |> send_resp(status, body["error"]) |> halt()
          end
        )

      assert conn.halted
      assert conn.status == 401
      assert conn.resp_body == "invalid_token"
      assert ["host"] = get_resp_header(conn, "x-rendered-by")
      assert Telemetry.outcome(conn) == :missing_credentials
      assert_span(:authenticate, %{outcome: :missing_credentials})
    end

    test "a custom :www_authenticate override does not hide the outcome", %{config: config} do
      conn =
        :post
        |> conn("/mcp")
        |> Factory.authenticate(config,
          www_authenticate: fn conn, _challenge -> put_resp_header(conn, "www-authenticate", "Custom") end
        )

      assert conn.status == 401
      assert_span(:authenticate, %{outcome: :missing_credentials, status: 401})
    end

    test "a raising verifier emits :exception with only its kind and re-raises", %{config: config} do
      request = config |> Factory.access_token() |> bearer()

      assert_raise RuntimeError, "verifier exploded", fn ->
        Factory.authenticate(request, config, verify: fn _config, _token, _opts -> raise "verifier exploded" end)
      end

      assert_receive {:telemetry, [:attesto_mcp, :authenticate, :start], _measurements, _metadata}
      assert_receive {:telemetry, [:attesto_mcp, :authenticate, :exception], measurements, metadata}
      assert is_integer(measurements.duration)
      assert Map.keys(metadata) |> Enum.sort() == [:kind, :telemetry_span_context]
      assert metadata.kind == :error
      refute_received {:telemetry, [:attesto_mcp, :authenticate, :stop], _measurements, _metadata}
    end

    test "a stale outcome from an earlier plug is cleared before verification", %{config: config} do
      conn =
        :post
        |> conn("/mcp")
        |> Telemetry.put_outcome(:ok)
        |> Factory.authenticate(config)

      assert conn.halted
      assert Telemetry.outcome(conn) == :missing_credentials
    end
  end

  describe "[:attesto_mcp, :require_scopes]" do
    defp require_scopes(conn, scopes), do: RequireScopes.call(conn, RequireScopes.init(scopes: scopes))

    test "a granted scope stops with :ok", %{config: config} do
      conn =
        config
        |> Factory.access_token(scopes: [Scopes.tools_call()])
        |> bearer()
        |> Factory.authenticate(config)
        |> require_scopes([Scopes.tools_call()])

      refute conn.halted
      assert_span(:authenticate, %{outcome: :ok})
      metadata = assert_span(:require_scopes, %{outcome: :ok, status: nil})
      refute Map.has_key?(metadata, :binding)
    end

    test "a missing scope is :insufficient_scope and replaces the authentication outcome", %{config: config} do
      conn =
        config
        |> Factory.access_token(scopes: [Scopes.resources_read()])
        |> bearer()
        |> Factory.authenticate(config)
        |> require_scopes([Scopes.tools_call()])

      assert conn.status == 403
      assert Telemetry.outcome(conn) == :insufficient_scope
      assert_span(:authenticate, %{outcome: :ok})
      assert_span(:require_scopes, %{outcome: :insufficient_scope, status: 403})
    end

    test "a scope check on an unauthenticated connection is :unauthenticated" do
      conn = :post |> conn("/mcp") |> require_scopes([Scopes.tools_call()])

      assert conn.status == 401
      assert_span(:require_scopes, %{outcome: :unauthenticated, status: 401})
    end

    test "ProtectResource emits both spans, including through authorize/3", %{config: config} do
      protection = ProtectResource.init(config: config, htu: &Factory.htu/1, scopes: [Scopes.tools_call()])

      composed =
        config
        |> Factory.access_token(scopes: [Scopes.resources_read()])
        |> bearer()
        |> ProtectResource.call(protection)

      assert composed.status == 403
      assert_span(:authenticate, %{outcome: :ok})
      assert_span(:require_scopes, %{outcome: :insufficient_scope, status: 403})

      prepared = ProtectResource.prepare(config: config, htu: &Factory.htu/1)

      split =
        config
        |> Factory.access_token(scopes: [Scopes.tools_call()])
        |> bearer()
        |> ProtectResource.authenticate(prepared)
        |> ProtectResource.authorize(prepared, [Scopes.tools_call()])

      refute split.halted
      assert_span(:authenticate, %{outcome: :ok})
      assert_span(:require_scopes, %{outcome: :ok})
    end
  end

  describe "refusal_outcome/2" do
    test "maps every refusal the core plug renders to a bounded atom" do
      for {status, body, outcome} <- [
            {503, %{"error" => "temporarily_unavailable"}, :verifier_unavailable},
            {403, %{"error" => "insufficient_scope"}, :insufficient_scope},
            {401, %{"error" => "use_dpop_nonce"}, :dpop_nonce_required},
            {401, %{"error" => "invalid_dpop_proof", "error_description" => "replay"}, :dpop_replay},
            {401, %{"error" => "invalid_dpop_proof", "error_description" => "htu_mismatch"}, :invalid_dpop_proof},
            {401, %{"error" => "insufficient_user_authentication"}, :step_up_required},
            {401, %{"error" => "invalid_token", "error_description" => "invalid_issuer"}, :invalid_issuer},
            {401, %{"error" => "invalid_token", "error_description" => "mtls_cert_required"},
             :sender_constraint_mismatch},
            {401, %{"error" => "invalid_token", "error_description" => "invalid_signature"}, :invalid_token},
            {401, %{"error" => "invalid_token"}, :invalid_token},
            {401, %{"error" => "unknown"}, :invalid_token},
            {403, %{"error" => "unknown"}, :insufficient_scope},
            {418, %{"error" => "unknown"}, :other},
            {401, "not a map", :invalid_token}
          ] do
        assert Telemetry.refusal_outcome(status, body) == outcome, inspect({status, body})
      end
    end
  end
end
