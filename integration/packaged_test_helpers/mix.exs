defmodule AttestoMCP.PackagedTestHelpersConsumer.MixProject do
  use Mix.Project

  def project do
    [
      app: :attesto_mcp_packaged_test_helpers_consumer,
      version: "0.0.0",
      elixir: "~> 1.18",
      deps: [
        {:attesto_mcp, path: System.fetch_env!("ATTESTO_MCP_PACKAGE_PATH"), override: true}
      ]
    ]
  end

  def application, do: [extra_applications: [:logger]]
end
