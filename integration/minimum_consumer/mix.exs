defmodule AttestoMCP.MinimumConsumer.MixProject do
  use Mix.Project

  def project do
    [
      app: :attesto_mcp_minimum_consumer,
      version: "0.0.0",
      elixir: "~> 1.18",
      deps: deps()
    ]
  end

  def application, do: [extra_applications: [:logger]]

  defp deps do
    [
      {:attesto_mcp, path: "../..", override: true},
      {:attesto, "== 1.3.0", override: true},
      {:jose, "== 1.11.12", override: true},
      {:plug, "== 1.16.6", override: true},
      {:phoenix, "== 1.7.24", override: true}
    ]
  end
end
