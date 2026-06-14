defmodule AttestoMCP.MixProject do
  @moduledoc false
  use Mix.Project

  alias AttestoMCP.Plug.Authenticate
  alias AttestoMCP.Plug.ProtectResource
  alias AttestoMCP.Plug.RequireScopes
  alias AttestoMCP.Test.DPoPAssertions
  alias AttestoMCP.Test.DPoPReplay

  @version "0.6.2"
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
      {:attesto, "~> 0.6"},
      {:plug, "~> 1.16"},

      # Optional: only needed by AttestoMCP.Router and AttestoMCP.MetadataController.
      # Plug-only consumers (and the Authenticate/RequireScopes/ProtectResource
      # plugs) do not require it. Phoenix apps already depend on it directly.
      {:phoenix, "~> 1.7", optional: true},

      # Optional: only needed by the `mix attesto_mcp.install` Igniter task.
      # Library consumers never call the installer at runtime, so the dependency
      # stays out of their closure unless they opt into the codegen tooling.
      {:igniter, "~> 0.5", optional: true},

      # dev / quality
      {:ex_doc, "~> 0.40", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:quokka, "~> 2.12", only: [:dev, :test], runtime: false}
    ]
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
