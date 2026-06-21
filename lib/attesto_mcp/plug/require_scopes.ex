defmodule AttestoMCP.Plug.RequireScopes do
  @moduledoc """
  Require scopes on a request authenticated by `AttestoMCP.Plug.Authenticate`.

  The plug reads the verified scope list from `conn.assigns` and checks it with
  `Attesto.Scope` (the same scope algebra `Attesto.Plug.RequireScopes` uses). It
  does not encode MCP policy; routes choose their own required scopes.

      plug AttestoMCP.Plug.RequireScopes, scopes: [AttestoMCP.Scopes.tools_call()]

  Rejections are rendered through `Attesto.Plug.OAuthError`: a request that is
  not authenticated gets a 401 `invalid_token`, and an authenticated request
  that is missing a required scope gets a 403 `insufficient_scope` (RFC 6750
  §3.1). Both delegate to `Attesto.Plug.OAuthError`, threading the per-request
  `:www_authenticate` / `:send_error` transport hooks
  `AttestoMCP.Plug.ProtectResource` injects, so a scope rejection carries the
  same RFC 9728 `resource_metadata` challenge and host-controlled error envelope
  the authentication rejection does.

  This plug reads MCP-specific assign keys (`:attesto_mcp_claims` /
  `:attesto_mcp_scopes`, set by `AttestoMCP.Plug.Authenticate`) and a pre-split
  granted-scope list; that is why it is a thin wrapper over the OAuthError
  renderer rather than a direct use of `Attesto.Plug.RequireScopes` (which reads
  the `scope` claim under its own key).
  """

  @behaviour Plug

  alias Attesto.Plug.OAuthError
  alias Attesto.Scope

  @claims_key :attesto_mcp_claims
  @scopes_key :attesto_mcp_scopes

  @impl Plug
  def init(opts) when is_list(opts) do
    required = normalize_required(opts)

    if required == [] do
      raise ArgumentError, "AttestoMCP.Plug.RequireScopes requires at least one scope"
    end

    %{
      catalog: Scope.new_catalog(required),
      claims_key: Keyword.get(opts, :claims_key, @claims_key),
      required: required,
      scopes_key: Keyword.get(opts, :scopes_key, @scopes_key),
      transport: Keyword.take(opts, [:send_error, :www_authenticate, :no_store])
    }
  end

  @impl Plug
  def call(conn, opts) do
    granted = Map.get(conn.assigns, opts.scopes_key)

    cond do
      is_list(granted) and Scope.grants_all?(opts.catalog, granted, opts.required) ->
        conn

      is_list(granted) ->
        OAuthError.insufficient_scope(
          conn,
          opts.required,
          scheme_of(conn.assigns[opts.claims_key]),
          opts.transport
        )

      true ->
        OAuthError.unauthorized(
          conn,
          :bearer,
          "invalid_token",
          Keyword.put(opts.transport, :description, "request is not authenticated")
        )
    end
  end

  defp normalize_required(opts) do
    cond do
      Keyword.keyword?(opts) and is_binary(Keyword.get(opts, :scope)) ->
        [Keyword.fetch!(opts, :scope)]

      Keyword.keyword?(opts) ->
        List.wrap(Keyword.get(opts, :scopes, []))

      true ->
        List.wrap(opts)
    end
  end

  defp scheme_of(%{"cnf" => %{"jkt" => jkt}}) when is_binary(jkt), do: :dpop
  defp scheme_of(_claims), do: :bearer
end
