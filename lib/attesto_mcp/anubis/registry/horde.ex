if Code.ensure_loaded?(Anubis.Server.Registry) and Code.ensure_loaded?(Horde.Registry) do
  defmodule AttestoMCP.Anubis.Registry.Horde do
    @moduledoc """
    `Horde.Registry`-backed session registry for the Anubis MCP transports.

    ## Cluster-wide registration

    Anubis 1.7 and later safely name client-supplied session IDs through an
    Elixir `Registry`; its bundled `Anubis.Server.Registry.PG` can route
    requests to live sessions across connected nodes. This adapter is for hosts
    that also want Horde's CRDT-backed cluster-wide name ownership, so one
    distributed registry coordinates session names and lookup.

    This adapter implements `session_name/2`, returning a `:via` tuple:

        {:via, Horde.Registry, {registry_name, session_id}}

    Because Anubis passes that name to the session `GenServer.start_link/3`, the
    session auto-registers in the CRDT-backed `Horde.Registry` on start. The
    `session_id` is kept as ETS/CRDT data. Horde gives cluster-wide name
    uniqueness and resolves a registered name to the owning (possibly remote)
    pid, so a request that lands on any node routes transparently to the node
    holding the session.

    Anubis starts the session `DynamicSupervisor` itself, so this adapter only
    starts the `Horde.Registry`; cross-node request routing is handled by
    distributed Erlang `GenServer.call/3` against the pid that
    `Horde.Registry.lookup/2` returns, exactly as the `:pg` adapter relied on.

    ## Wiring

        {MyApp.MCP.Server,
         transport: :streamable_http,
         registry: {AttestoMCP.Anubis.Registry.Horde, []},
         # ...
        }

    Cluster membership uses `members: :auto`, so every node running the same
    Anubis registry name discovers its peers (pair it with a clustering library
    such as `libcluster` so the nodes connect).

    Compile-guarded on `Anubis.Server.Registry` and `Horde.Registry`.
    """

    @behaviour Anubis.Server.Registry

    @doc """
    Starts the `Horde.Registry` for the given Anubis registry name.

    Anubis injects `:name` (a compile-time bounded atom such as
    `:"Anubis.MyApp.MCP.Server.registry"`) into `opts`. `keys: :unique` is
    required for `:via` registration; `members: :auto` lets Horde discover peers
    running the same registry name across the connected cluster.
    """
    @impl Anubis.Server.Registry
    def child_spec(opts) do
      # Anubis injects `:name`; require it for a clear error. `keys: :unique` is
      # mandatory for `:via` registration so it is forced. Any other caller opt
      # (custom CRDT/`:delta_crdt_options`, `:listeners`, an explicit `:members`
      # list for non-auto clustering) is preserved; `:members` defaults to `:auto`.
      _ = Keyword.fetch!(opts, :name)

      opts
      |> Keyword.put(:keys, :unique)
      |> Keyword.put_new(:members, :auto)
      |> Horde.Registry.child_spec()
    end

    @doc """
    Returns the `:via` tuple Anubis uses as the session `GenServer` name.

    Returning a `:via` tuple (rather than an atom) means the session registers
    itself in `Horde.Registry` on `start_link`, so `register_session/3` is a
    no-op and no atom is ever derived from the `session_id`.
    """
    @impl Anubis.Server.Registry
    def session_name(registry_name, session_id) do
      {:via, Horde.Registry, {registry_name, session_id}}
    end

    @doc """
    No-op: the session registers itself via the `:via` tuple from `session_name/2`
    when it starts.
    """
    @impl Anubis.Server.Registry
    def register_session(_registry_name, _session_id, _pid), do: :ok

    @doc "Looks the session pid up in the cluster-wide `Horde.Registry`."
    @impl Anubis.Server.Registry
    def lookup_session(registry_name, session_id) do
      case Horde.Registry.lookup(registry_name, session_id) do
        [{pid, _value} | _rest] -> {:ok, pid}
        [] -> {:error, :not_found}
      end
    end

    @doc """
    No-op: `Horde.Registry` removes the entry automatically when the owning
    session process exits.

    `Horde.Registry.unregister/2` only unregisters names owned by the *calling*
    process; here the caller is the transport, not the session, so an explicit
    unregister would be a misleading no-op. Anubis terminates sessions through the
    session `DynamicSupervisor`, and the resulting process exit drops the Horde
    entry. Anubis never invokes this callback itself; it exists only to satisfy
    the behaviour.
    """
    @impl Anubis.Server.Registry
    def unregister_session(_registry_name, _session_id), do: :ok
  end
end
