defmodule AttestoMCP.Telemetry do
  @moduledoc """
  `:telemetry` events for the MCP authentication and scope boundaries.

  Every `AttestoMCP.Plug.Authenticate` call, and so every
  `AttestoMCP.Plug.ProtectResource` authentication, is wrapped in a span, as
  is every `AttestoMCP.Plug.RequireScopes` decision. A `:stop` event names the
  outcome with one atom from a bounded set, so an operator can count how
  often clients fail to authenticate and why without reading request logs.

  ## Events

  ### `[:attesto_mcp, :authenticate, :start | :stop | :exception]`

  `:start` measurements: `:system_time` and `:monotonic_time`. `:stop`
  measurements: `:duration` (native time units) and `:monotonic_time`. `:stop`
  metadata:

    * `:outcome` - one of the outcomes below.
    * `:status` - the HTTP status of a refusal (401, 403, or 503); `nil` when
      the request was authenticated.
    * `:binding` - `:bearer`, `:dpop`, or `:mtls` for an authenticated
      request; `nil` for a refusal.

  `:exception` carries `:duration` and the metadata `:kind` only; the
  exception is re-raised afterwards. Every event carries a
  `:telemetry_span_context` reference shared by the span's events.

  ### `[:attesto_mcp, :require_scopes, :start | :stop | :exception]`

  The same measurements. `:stop` metadata is `:outcome` (`:ok`,
  `:insufficient_scope`, or `:unauthenticated`) and `:status`.

  ## Outcomes

    * `:ok` - authenticated, or every required scope is granted.
    * `:missing_credentials` - no access token, or a malformed
      `Authorization` header.
    * `:invalid_token` - the token failed verification for a reason not
      listed separately: signature, format, or claims.
    * `:token_expired` and `:token_not_yet_valid` - the token's validity
      window excludes the current time.
    * `:invalid_audience` and `:invalid_issuer` - the token names another
      resource or another issuer.
    * `:sender_constraint_mismatch` - the token is bound to a DPoP key or a
      client certificate that the request did not present, presented a
      different one, or presented one the token is not bound to.
    * `:invalid_dpop_proof` - the DPoP proof failed verification.
    * `:dpop_replay` - the DPoP proof's `jti` had already been seen.
    * `:dpop_nonce_required` - the client must retry with the issued
      `DPoP-Nonce` (RFC 9449 §8).
    * `:step_up_required` - the token does not meet the route's RFC 9470
      step-up requirement.
    * `:policy_rejected` - the host's `:principal` callback refused the
      verified claims.
    * `:insufficient_scope` - the token lacks a required scope.
    * `:unauthenticated` - a scope check ran on a connection no
      authentication boundary had verified.
    * `:verifier_unavailable` - the verifier's dependency (JWKS, introspection)
      could not be reached, so the request was answered 503.
    * `:other` - a refusal outside this set.

  ## What metadata contains

  Outcomes, statuses, and bindings only. Tokens, DPoP proofs, claims,
  principals, granted or required scopes, `error_description` text, callback
  return values, and exception reasons never enter telemetry metadata.
  """

  import Plug.Conn

  @outcome_key :attesto_mcp_auth_outcome
  @sender_constraint ~w(
    invalid_dpop_jkt invalid_mtls_thumbprint dpop_proof_required dpop_proof_unexpected
    mtls_cert_required mtls_cert_unexpected conflicting_confirmation unsupported_confirmation
  )

  @typedoc "A bounded authentication or authorization outcome."
  @type outcome ::
          :ok
          | :missing_credentials
          | :invalid_token
          | :token_expired
          | :token_not_yet_valid
          | :invalid_audience
          | :invalid_issuer
          | :sender_constraint_mismatch
          | :invalid_dpop_proof
          | :dpop_replay
          | :dpop_nonce_required
          | :step_up_required
          | :policy_rejected
          | :insufficient_scope
          | :unauthenticated
          | :verifier_unavailable
          | :other

  @doc """
  The outcome recorded on a connection by the last `AttestoMCP` plug that
  authenticated or refused it, or `nil` when none has run.

  It is stored under `conn.private[:attesto_mcp_auth_outcome]`, which a host
  or a downstream package may read directly.
  """
  @spec outcome(Plug.Conn.t()) :: outcome() | nil
  def outcome(%Plug.Conn{private: private}), do: Map.get(private, @outcome_key)

  @doc false
  @spec outcome_key() :: atom()
  def outcome_key, do: @outcome_key

  @doc false
  @spec put_outcome(Plug.Conn.t(), outcome() | nil) :: Plug.Conn.t()
  def put_outcome(conn, outcome), do: put_private(conn, @outcome_key, outcome)

  @doc false
  # Runs `fun`, which returns `{conn, stop_metadata}`, inside a
  # `[:attesto_mcp, name]` span. An exception emits only its kind and is
  # re-raised: a verifier failure must not change the response, and its reason
  # may describe the request in more detail than telemetry should carry.
  @spec span(atom(), (-> {Plug.Conn.t(), map()})) :: Plug.Conn.t()
  def span(name, fun) when is_atom(name) and is_function(fun, 0) do
    context = %{telemetry_span_context: make_ref()}
    started = System.monotonic_time()

    :telemetry.execute(
      [:attesto_mcp, name, :start],
      %{system_time: System.system_time(), monotonic_time: started},
      context
    )

    try do
      {conn, metadata} = fun.()
      stopped = System.monotonic_time()

      :telemetry.execute(
        [:attesto_mcp, name, :stop],
        %{duration: stopped - started, monotonic_time: stopped},
        Map.merge(context, metadata)
      )

      conn
    catch
      kind, reason ->
        :telemetry.execute(
          [:attesto_mcp, name, :exception],
          %{duration: System.monotonic_time() - started},
          Map.put(context, :kind, kind)
        )

        :erlang.raise(kind, reason, __STACKTRACE__)
    end
  end

  @doc false
  # Installed as the `:send_error` transport hook of the core plug so every
  # refusal records its outcome before the host's own hook, or the default
  # JSON envelope, renders it. The hook sees the OAuth error code and
  # description the core chose, which is more exact than the rendered
  # response, and it runs whatever `:www_authenticate` override the host uses.
  @spec send_error(Plug.Conn.t(), pos_integer(), map(), term(), outcome() | nil) :: Plug.Conn.t()
  def send_error(conn, status, body, host, outcome \\ nil) do
    conn
    |> put_outcome(outcome || refusal_outcome(status, body))
    |> deliver_error(status, body, host)
  end

  @doc false
  @spec wrap_send_error(keyword()) :: keyword()
  def wrap_send_error(opts) do
    case Keyword.get(opts, :send_error) do
      {__MODULE__, :send_error, _extra} -> opts
      host -> Keyword.put(opts, :send_error, {__MODULE__, :send_error, [host]})
    end
  end

  @doc false
  @spec stop_metadata(Plug.Conn.t(), atom() | nil) :: map()
  def stop_metadata(conn, sender_key \\ nil) do
    if conn.halted do
      %{outcome: outcome(conn) || status_outcome(conn.status), status: conn.status, binding: nil}
    else
      %{outcome: :ok, status: nil, binding: binding(conn, sender_key)}
    end
  end

  @doc false
  @spec refusal_outcome(pos_integer(), map()) :: outcome()
  def refusal_outcome(503, _body), do: :verifier_unavailable

  def refusal_outcome(status, %{"error" => error} = body),
    do: error_outcome(error, Map.get(body, "error_description"), status)

  def refusal_outcome(status, _body), do: status_outcome(status)

  defp error_outcome("insufficient_scope", _description, _status), do: :insufficient_scope
  defp error_outcome("use_dpop_nonce", _description, _status), do: :dpop_nonce_required
  defp error_outcome("invalid_dpop_proof", "replay", _status), do: :dpop_replay
  defp error_outcome("invalid_dpop_proof", _description, _status), do: :invalid_dpop_proof
  defp error_outcome("insufficient_user_authentication", _description, _status), do: :step_up_required
  defp error_outcome("invalid_token", description, _status), do: token_outcome(description)
  defp error_outcome(_error, _description, status), do: status_outcome(status)

  # The core plug reports a verification failure as the verifier's reason
  # atom in `error_description`; these are the reasons worth counting apart.
  defp token_outcome("missing or malformed Authorization header"), do: :missing_credentials
  defp token_outcome("expired"), do: :token_expired
  defp token_outcome("not_yet_valid"), do: :token_not_yet_valid
  defp token_outcome("invalid_audience"), do: :invalid_audience
  defp token_outcome("invalid_issuer"), do: :invalid_issuer
  defp token_outcome("request is not authenticated"), do: :unauthenticated

  defp token_outcome("request was not authenticated by this protected-resource boundary"), do: :unauthenticated

  defp token_outcome(reason) when reason in @sender_constraint, do: :sender_constraint_mismatch
  defp token_outcome(_reason), do: :invalid_token

  defp status_outcome(401), do: :invalid_token
  defp status_outcome(403), do: :insufficient_scope
  defp status_outcome(503), do: :verifier_unavailable
  defp status_outcome(_status), do: :other

  defp binding(_conn, nil), do: nil

  defp binding(conn, sender_key) do
    case Map.get(conn.assigns, sender_key) do
      %{binding: binding} when binding in [:bearer, :dpop, :mtls] -> binding
      _other -> nil
    end
  end

  defp deliver_error(conn, status, body, fun) when is_function(fun, 3), do: fun.(conn, status, body)

  defp deliver_error(conn, status, body, {module, fun}) when is_atom(module) and is_atom(fun),
    do: apply(module, fun, [conn, status, body])

  defp deliver_error(conn, status, body, {module, fun, extra}) when is_atom(module) and is_atom(fun) and is_list(extra),
    do: apply(module, fun, [conn, status, body | extra])

  # The core plug's default envelope, reproduced so a host without a hook
  # gets the same response it always has.
  defp deliver_error(conn, status, body, _none) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, JSON.encode!(body))
    |> halt()
  end
end
