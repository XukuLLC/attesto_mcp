defmodule AttestoMCP.MixProject do
  @moduledoc false
  use Mix.Project

  alias AttestoMCP.Anubis.JSONSafe
  alias AttestoMCP.Anubis.Registry.Horde
  alias AttestoMCP.Anubis.Session
  alias AttestoMCP.Plug.Authenticate
  alias AttestoMCP.Plug.ProtectResource
  alias AttestoMCP.Plug.RequireScopes
  alias AttestoMCP.Test.DPoPAssertions
  alias AttestoMCP.Test.DPoPReplay

  @version "1.2.1"
  @url "https://github.com/XukuLLC/attesto_mcp"
  @maintainers ["Neil Berkman"]

  def project do
    [
      name: "AttestoMCP",
      app: :attesto_mcp,
      version: @version,
      elixir: "~> 1.18",
      package: package(),
      source_url: @url,
      homepage_url: @url,
      maintainers: @maintainers,
      description: "Plug/Phoenix authentication helpers for protecting Model Context Protocol servers with Attesto.",
      deps: deps(),
      docs: docs(),
      elixirc_paths: elixirc_paths(Mix.env()),
      aliases: aliases()
    ]
  end

  def cli do
    [preferred_envs: [precommit: :test, check: :test]]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      attesto_dep(),
      {:plug, "~> 1.16.6 or ~> 1.17.4 or ~> 1.18.5 or ~> 1.19.5 or >= 1.20.3 and < 2.0.0"},

      # Optional: only needed by AttestoMCP.Router and AttestoMCP.MetadataController.
      # Plug-only consumers (and the Authenticate/RequireScopes/ProtectResource
      # plugs) do not require it. Phoenix apps already depend on it directly.
      {:phoenix, "~> 1.7.24 or >= 1.8.9 and < 2.0.0", optional: true},

      # Optional: only needed by the `mix attesto_mcp.install` Igniter task.
      # Library consumers never call the installer at runtime, so the dependency
      # stays out of their closure unless they opt into the codegen tooling.
      {:igniter, ">= 0.6.0 and < 1.0.0", optional: true},

      # Optional: only needed by `AttestoMCP.Anubis`, the frame-auth bridge for
      # hosts running an Anubis MCP server. The module is compile-guarded on
      # `Anubis.Server.Frame`, so a resource server that does not use Anubis
      # never compiles it and never pulls anubis_mcp into its closure. Declared
      # here (not `only:`) so it is loadable when attesto_mcp builds the bridge
      # and its tests.
      {:anubis_mcp, ">= 1.7.0 and < 2.0.0", optional: true},

      # Optional: only needed by `AttestoMCP.Anubis.SessionStore.Ecto` (and its
      # `AttestoMCP.Anubis.Session` schema), a Postgres-backed
      # `Anubis.Server.Session.Store` adapter. The modules are compile-guarded on
      # `Ecto.Schema`, so a consumer that does not persist MCP sessions never
      # compiles them and never pulls Ecto into its closure.
      {:ecto, "~> 3.10", optional: true},

      # Optional: only needed by `AttestoMCP.Anubis.Registry.Horde`, a
      # cluster-wide `Anubis.Server.Registry` adapter. Compile-guarded on
      # `Horde.Registry`, so a single-node consumer never compiles it.
      {:horde, "~> 0.9", optional: true},

      # test-only: the Ecto session-store adapter's behaviour-conformance tests
      # run against a real Postgres repo (`AttestoMCP.TestRepo`); a consumer's
      # own host application supplies `ecto_sql` + a driver.
      {:ecto_sql, "~> 3.10", only: :test},
      {:postgrex, ">= 0.22.4 and < 1.0.0", only: :test},

      # test-only: the `mix attesto_mcp.install` tests drive a synthetic Phoenix
      # project via `Igniter.Test.phx_test_project/1`, which needs igniter's
      # `Igniter.Phoenix.Single` - itself compile-guarded on `Phx.New.Project`
      # from phx_new. A host running the installer patches its existing router
      # and never needs phx_new, so it is test-only here.
      {:phx_new, "~> 1.7", only: :test, runtime: false},

      # dev / quality
      {:ex_doc, "~> 0.40", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:quokka, "~> 2.12", only: [:dev, :test], runtime: false}
    ]
  end

  # Co-develop against the sibling attesto checkout ONLY when explicitly opted in
  # via `ATTESTO_PATH=1` (and the checkout exists); otherwise the published Hex
  # package. This is gated on the env var, not just `File.dir?`, so `mix
  # hex.publish` (which runs in :dev with the sibling on disk) resolves the Hex
  # constraint rather than a path dep, which cannot be packaged. Requires
  # Attesto 1.2.5 supplies strict trusted RFC 8707 audience policy, the
  # advisory-safe Plug compatibility ranges, and the JOSE 1.11.12 floor needed
  # for both Erlang/OTP 28 EC key compatibility and correct nil-to-JSON-null
  # encoding, plus the
  # Static keystore signing_alg/kid labelling fix, RFC 9470 step-up (the
  # `:step_up` plug option and
  # `Attesto.Plug.OAuthError.insufficient_user_authentication/4`), and the
  # `Attesto.Plug.{OAuthError,RequireScopes}` transport hooks this MCP layer
  # delegates to.
  defp attesto_dep do
    if System.get_env("ATTESTO_PATH") in ~w(1 true) and File.dir?("../attesto") do
      {:attesto, path: "../attesto", override: true}
    else
      {:attesto, ">= 1.12.2 and < 2.0.0"}
    end
  end

  defp aliases do
    [
      precommit: [
        "format --check-formatted",
        "compile --warnings-as-errors",
        "credo --strict",
        "test"
      ],
      check: [
        "format --check-formatted",
        "compile --warnings-as-errors",
        "test",
        "credo --strict"
      ]
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @url,
      extras: ["README.md", "guides/mcp_wiring.md", "guides/proxy_origin.md", "CHANGELOG.md", "LICENSE"],
      groups_for_extras: [
        Guides: ~r/guides\/.?/,
        Changelog: ~r/CHANGELOG\.md/,
        License: ~r/LICENSE/
      ],
      groups_for_modules: [
        Setup: [AttestoMCP],
        Plugs: [Authenticate, RequireScopes, ProtectResource],
        Routing: [AttestoMCP.Router, AttestoMCP.MetadataController],
        Metadata: [AttestoMCP.Metadata],
        Scopes: [AttestoMCP.Scopes],
        Anubis: [
          AttestoMCP.Anubis,
          AttestoMCP.Anubis.SessionStore.Ecto,
          Session,
          Horde,
          JSONSafe
        ],
        Testing: [DPoPReplay, DPoPAssertions]
      ]
    ]
  end

  defp package do
    [
      maintainers: @maintainers,
      licenses: ["MIT"],
      links: %{
        "Changelog" => "https://hexdocs.pm/attesto_mcp/changelog.html",
        "GitHub" => @url
      },
      files: ~w(lib guides LICENSE mix.exs README.md CHANGELOG.md)
    ]
  end
end
