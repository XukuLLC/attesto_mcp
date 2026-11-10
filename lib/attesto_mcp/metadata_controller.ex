if Code.ensure_loaded?(Phoenix.Controller) do
  defmodule AttestoMCP.MetadataController do
    @moduledoc """
    Phoenix controller that serves RFC 9728 protected-resource metadata.

    Routes mounted by `AttestoMCP.Router.attesto_mcp_protected_resource_metadata/2`
    dispatch here. The controller reads the resource path and metadata options
    placed in `conn.private` by the route, builds the document with
    `AttestoMCP.Metadata.protected_resource/3`, and renders it as JSON. The
    `resource` identifier comes from `AttestoMCP.Metadata.resolve_origin/2`.
    The authorization server must be supplied by `:authorization_servers`,
    `:issuer`, or `:config`; it is never derived from the request authority.

    Because the `resource` identifier is resolved the same way
    `AttestoMCP.Plug.ProtectResource` resolves its `WWW-Authenticate`
    `resource_metadata` challenge, the discovered metadata URL and the served
    `resource` value match - provided both call sites receive the same origin
    (with no pin they both derive from the request; behind a proxy pass the same
    `:base_url`/`:origin` to the router macro and the plug).

    A document with a configured `:base_url`, `:origin`, or `:resource` is
    served with `Cache-Control: public, max-age=3600`. A document whose
    `resource` is derived from the request `Host` is served with
    `Cache-Control: no-store`.

    The controller compiles only when Phoenix is available; Plug-only consumers
    do not pull it in.
    """

    use Phoenix.Controller, formats: [:json]

    alias AttestoMCP.Metadata

    @cache_max_age_seconds 3600

    @doc """
    Render protected-resource metadata for the resource bound to this route.
    """
    @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
    def show(conn, _params) do
      resource_path = Map.fetch!(conn.private, :attesto_mcp_resource_path)
      opts = Map.get(conn.private, :attesto_mcp_metadata_opts, [])

      metadata = Metadata.protected_resource(conn, resource_path, metadata_opts(opts))

      conn
      |> Plug.Conn.put_resp_header("cache-control", cache_control(opts))
      |> json(metadata)
    end

    # With a configured `resource` or `:base_url`/`:origin`, the document
    # carries no secrets and is identical for every caller, and RFC 9728 §3.1
    # permits caching it, so it is served with the same public one-hour policy
    # as AttestoPhoenix's protected-resource metadata. Without one, `resource`
    # is built from the request `Host`, and a shared cache that does not key on
    # that host would serve one caller's document to every other caller.
    defp cache_control(opts) do
      if Enum.any?([:resource, :base_url, :origin], &Keyword.has_key?(opts, &1)),
        do: "public, max-age=#{@cache_max_age_seconds}",
        else: "no-store"
    end

    # `:scopes` is the ergonomic name on the router macro; the RFC 9728 field is
    # `scopes_supported`. Translate it unless the host passed the field directly.
    defp metadata_opts(opts) do
      case Keyword.fetch(opts, :scopes) do
        {:ok, scopes} ->
          opts
          |> Keyword.delete(:scopes)
          |> Keyword.put_new(:scopes_supported, scopes)

        :error ->
          opts
      end
    end
  end
end
