# Module name is `Mix.Tasks.AttestoMcp.Install` (not `AttestoMCP`) because Mix
# resolves `mix attesto_mcp.install` via `Mix.Utils.command_to_module_name/1`,
# which camelizes each underscore-delimited segment and yields `AttestoMcp`. The
# task will not be found under any other casing. Every reference to the library
# itself keeps the `AttestoMCP` acronym casing.
defmodule Mix.Tasks.AttestoMcp.Install.Docs do
  @moduledoc false

  @spec short_doc() :: String.t()
  def short_doc, do: "Scaffolds an MCP protected resource into a Phoenix application"

  @spec example() :: String.t()
  def example,
    do:
      "mix attesto_mcp.install --config-module MyApp.Attesto --base-url https://mcp.example.com " <>
        "--resource-path /mcp --scopes mcp:use"

  @spec long_doc() :: String.t()
  def long_doc do
    """
    #{short_doc()}

    Wires the building blocks an MCP server needs to act as an OAuth 2.0
    protected resource into a host Phoenix application:

      * The OAuth 2.0 Protected Resource Metadata endpoint (RFC 9728 Section 3),
        mounted from the per-resource well-known path (RFC 9728 Section 3.1) with
        the same route form emitted by
        `AttestoMCP.Router.attesto_mcp_protected_resource_metadata/2`. The
        installer emits `root: false`, so multiple installations never create
        an ambiguous or order-dependent root document; a host may explicitly
        nominate one resource later if legacy-client compatibility requires it.
      * A Phoenix pipeline that enforces bearer-token authentication and the
        required OAuth scopes (RFC 6750 Bearer Token Usage, RFC 6749 Section 3.3
        scope semantics) via `AttestoMCP.Plug.ProtectResource`. The generated
        protection derives the exact resource audience from the same path as
        metadata and rejects tokens issued to sibling MCP resources.

    This task is idempotent per resource path: re-running it recognizes only a
    complete matching scaffold, so it will not duplicate the pipeline, metadata,
    or protected scope. Legacy raw metadata routes, implicit root ownership, and
    partial target wiring produce an actionable issue without changing the router;
    make root ownership explicit and complete or remove the old scaffold before
    rerunning the installer.

    ## Example

    ```sh
    #{example()}
    ```

    ## Options

    * `--config-module` - required module that returns the Attesto configuration,
      for example `MyApp.Attesto`.
    * `--config-function` - zero-arity function on `--config-module`; defaults
      to `config`. The generated plug receives the escape-safe MFA
      `{MyApp.Attesto, :config}`.
    * `--base-url` - required canonical HTTPS origin of the protected resource,
      for example `https://mcp.example.com`. It is emitted into both the
      authentication pipeline and metadata route so the request `Host` cannot
      select the accepted token audience. Path prefixes are permitted; query,
      fragment, and userinfo are rejected.
    * `--resource-path` - the path component of the protected resource being
      served, for example `/mcp` (RFC 9728 Section 3.1). The metadata endpoint is
      mounted at `/.well-known/oauth-protected-resource<resource-path>` and the
      protecting pipeline is piped through the matching scope. Defaults to `/mcp`.
    * `--scopes` - a comma-separated list of OAuth scope strings the bearer token
      must carry to access the protected resource (RFC 6749 Section 3.3). Defaults
      to `mcp:use`.
    * `--router` - the Phoenix router module to wire the routes into. Defaults to
      the application's discovered router.
    """
  end
end

if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AttestoMcp.Install do
    @shortdoc Mix.Tasks.AttestoMcp.Install.Docs.short_doc()

    @moduledoc Mix.Tasks.AttestoMcp.Install.Docs.long_doc()

    use Igniter.Mix.Task

    alias AttestoMCP.Metadata
    alias AttestoMCP.Plug.ProtectResource
    alias Igniter.Code.Common
    alias Igniter.Code.Function
    alias Igniter.Code.Keyword, as: CodeKeyword
    alias Igniter.Code.Module, as: CodeModule
    alias Igniter.Code.String, as: CodeString
    alias Igniter.Libs.Phoenix
    alias Igniter.Mix.Task.Info
    alias Igniter.Project.Module, as: ProjectModule
    alias Mix.Tasks.AttestoMcp.Install.Docs

    @default_resource_path "/mcp"
    @default_scopes "mcp:use"

    @impl Igniter.Mix.Task
    def info(_argv, _composing_task) do
      %Info{
        group: :attesto_mcp,
        example: Docs.example(),
        schema: [
          config_module: :string,
          config_function: :string,
          base_url: :string,
          resource_path: :string,
          scopes: :string,
          router: :string
        ],
        aliases: []
      }
    end

    @impl Igniter.Mix.Task
    def igniter(igniter) do
      options = igniter.args.options

      with {:ok, config_mfa} <- config_mfa(options),
           {:ok, base_url} <- base_url(options) do
        install(igniter, options, config_mfa, base_url)
      else
        {:error, issue} -> Igniter.add_issue(igniter, issue)
      end
    end

    defp install(igniter, options, config_mfa, base_url) do
      resource_path = normalize_resource_path(options[:resource_path] || @default_resource_path)
      scopes = options[:scopes] |> Kernel.||(@default_scopes) |> parse_scopes!()
      router = resolve_router(igniter, options)
      pipeline_name = pipeline_name(resource_path)

      case installation_state(igniter, router, pipeline_name, resource_path, scopes, config_mfa, base_url) do
        {igniter, :installed} ->
          Igniter.add_notice(
            igniter,
            "AttestoMCP protected resource #{resource_path} is already installed; no router changes were made."
          )

        {igniter, :absent} ->
          igniter
          |> ensure_router_use(router)
          |> add_protect_pipeline(router, pipeline_name, resource_path, scopes, config_mfa, base_url)
          |> add_metadata_scope(router, resource_path, scopes, config_mfa, base_url)
          |> add_protected_scope(router, pipeline_name, resource_path)
          |> Igniter.add_notice("""
          AttestoMCP protected resource scaffolded for #{resource_path}.

          The host router now mounts the RFC 9728 path-inserted protected
          resource metadata endpoint (with no implicit root document) and a
          #{inspect(pipeline_name)} pipeline that enforces the #{inspect(scopes)}
          scope(s) and this resource's exact audience via
          AttestoMCP.Plug.ProtectResource using #{inspect(config_mfa)}.

          The canonical resource origin is pinned to #{inspect(base_url)} in both
          metadata and protection. The metadata document advertises the issuer
          returned by #{inspect(config_mfa)} as its authorization server.

          Next steps:

            * Mount your MCP transport plug inside the #{inspect(resource_path)} scope.
            * Keep the canonical base URL synchronized if the public resource
              origin changes.
          """)

        {igniter, {:conflict, issue}} ->
          Igniter.add_issue(igniter, issue)
      end
    end

    # Mount metadata through the public router macro so generated applications
    # inherit its RFC 9728 behavior. `root: false` is the safe repeatable default:
    # every resource gets its path-inserted document, and no install silently
    # claims a shared root whose meaning would depend on insertion order.
    defp add_metadata_scope(igniter, router, resource_path, scopes, config_mfa, base_url) do
      Phoenix.add_scope(
        igniter,
        "/",
        """
        attesto_mcp_protected_resource_metadata #{inspect(resource_path)},
          scopes: #{inspect(scopes)},
          config: #{inspect(config_mfa)},
          base_url: #{inspect(base_url)},
          root: false
        """,
        router: router
      )
    end

    # The protected resource itself is piped through the bearer-token pipeline
    # (RFC 6750). The MCP transport plug is mounted here by the application.
    defp add_protected_scope(igniter, router, pipeline_name, resource_path) do
      Phoenix.add_scope(
        igniter,
        resource_path,
        """
        pipe_through #{inspect(pipeline_name)}
        # Mount your MCP transport plug here.
        """,
        router: router
      )
    end

    defp add_protect_pipeline(igniter, router, pipeline_name, resource_path, scopes, config_mfa, base_url) do
      Phoenix.add_pipeline(
        igniter,
        pipeline_name,
        """
        plug :accepts, ["json"]
        plug AttestoMCP.Plug.ProtectResource,
          config: #{inspect(config_mfa)},
          scopes: #{inspect(scopes)},
          resource_path: #{inspect(resource_path)},
          base_url: #{inspect(base_url)},
          resource_audience: :resource
        """,
        router: router
      )
    end

    # Classify the existing router before any edit. This makes a complete new
    # scaffold byte-for-byte idempotent, while legacy raw routes, an implicit
    # single-resource root, or partial/manual wiring stop with migration advice
    # instead of being combined into duplicate or under-protected routes.
    defp installation_state(igniter, router, pipeline_name, resource_path, scopes, config_mfa, base_url) do
      {igniter, _source, zipper} = ProjectModule.find_module!(igniter, router)

      state = classify_installation(zipper, pipeline_name, resource_path, scopes, config_mfa, base_url)
      {igniter, state}
    end

    defp classify_installation(zipper, pipeline_name, resource_path, scopes, config_mfa, base_url) do
      cond do
        legacy_metadata_route?(zipper) ->
          {:conflict, legacy_route_issue(resource_path)}

        implicit_root_declaration?(zipper) ->
          {:conflict, implicit_root_issue(resource_path)}

        non_literal_metadata_declaration?(zipper) ->
          {:conflict, non_literal_metadata_issue(resource_path)}

        metadata_declaration?(zipper, resource_path) ->
          declared_installation_state(zipper, pipeline_name, resource_path, scopes, config_mfa, base_url)

        target_artifact?(zipper, pipeline_name, resource_path) ->
          {:conflict, partial_installation_issue(resource_path, scopes, config_mfa, base_url)}

        true ->
          :absent
      end
    end

    defp declared_installation_state(zipper, pipeline_name, resource_path, scopes, config_mfa, base_url) do
      if complete_installation?(zipper, pipeline_name, resource_path, scopes, config_mfa, base_url) do
        :installed
      else
        {:conflict, partial_installation_issue(resource_path, scopes, config_mfa, base_url)}
      end
    end

    defp complete_installation?(zipper, pipeline_name, resource_path, scopes, config_mfa, base_url) do
      router_uses_macro?(zipper) and
        complete_metadata_declaration?(zipper, resource_path, scopes, config_mfa, base_url) and
        complete_protection_pipeline?(zipper, pipeline_name, resource_path, scopes, config_mfa, base_url) and
        protected_scope?(zipper, pipeline_name, resource_path)
    end

    defp router_uses_macro?(zipper) do
      CodeModule.move_to_module_using(zipper, AttestoMCP.Router) != :error
    end

    defp metadata_declaration?(zipper, resource_path) do
      found?(
        Function.move_to_function_call(
          zipper,
          :attesto_mcp_protected_resource_metadata,
          [1, 2],
          &Function.argument_equals?(&1, 0, resource_path)
        )
      )
    end

    defp complete_metadata_declaration?(zipper, resource_path, scopes, config_mfa, base_url) do
      found?(
        Function.move_to_function_call(
          zipper,
          :attesto_mcp_protected_resource_metadata,
          2,
          fn declaration ->
            Function.argument_equals?(declaration, 0, resource_path) and
              Function.argument_matches_predicate?(
                declaration,
                1,
                &metadata_opts_match?(&1, scopes, config_mfa, base_url)
              )
          end
        )
      )
    end

    defp metadata_opts_match?(opts, scopes, config_mfa, base_url) do
      keyword_value_equals?(opts, :scopes, scopes) and
        keyword_literal_equals?(opts, :config, config_mfa) and
        keyword_value_equals?(opts, :base_url, base_url) and
        explicit_root?(opts)
    end

    defp explicit_root?(opts) do
      keyword_value_equals?(opts, :root, false) or keyword_value_equals?(opts, :root, true)
    end

    defp complete_protection_pipeline?(zipper, pipeline_name, resource_path, scopes, config_mfa, base_url) do
      found?(
        Function.move_to_function_call(zipper, :pipeline, 2, fn pipeline ->
          Function.argument_equals?(pipeline, 0, pipeline_name) and
            pipeline_protects_resource?(pipeline, resource_path, scopes, config_mfa, base_url)
        end)
      )
    end

    defp pipeline_declared?(zipper, pipeline_name) do
      found?(
        Function.move_to_function_call(
          zipper,
          :pipeline,
          2,
          &Function.argument_equals?(&1, 0, pipeline_name)
        )
      )
    end

    defp pipeline_protects_resource?(pipeline, resource_path, scopes, config_mfa, base_url) do
      found?(
        Common.within(pipeline, fn subtree ->
          Function.move_to_function_call(subtree, :plug, 2, fn plug ->
            Function.argument_equals?(plug, 0, ProtectResource) and
              Function.argument_matches_predicate?(
                plug,
                1,
                &protection_opts_match?(&1, resource_path, scopes, config_mfa, base_url)
              )
          end)
        end)
      )
    end

    defp protection_opts_match?(opts, resource_path, scopes, config_mfa, base_url) do
      keyword_literal_equals?(opts, :config, config_mfa) and
        keyword_value_equals?(opts, :scopes, scopes) and
        keyword_value_equals?(opts, :resource_path, resource_path) and
        keyword_value_equals?(opts, :base_url, base_url) and
        keyword_value_equals?(opts, :resource_audience, :resource)
    end

    defp protected_scope?(zipper, pipeline_name, resource_path) do
      found?(
        Function.move_to_function_call(zipper, :scope, [2, 3], fn scope ->
          Function.argument_equals?(scope, 0, resource_path) and
            scope_uses_pipeline?(scope, pipeline_name)
        end)
      )
    end

    defp scope_uses_pipeline?(scope, pipeline_name) do
      found?(
        Common.within(scope, fn subtree ->
          Function.move_to_function_call(
            subtree,
            :pipe_through,
            1,
            &Function.argument_equals?(&1, 0, pipeline_name)
          )
        end)
      )
    end

    defp target_artifact?(zipper, pipeline_name, resource_path) do
      pipeline_declared?(zipper, pipeline_name) or
        pipeline_referenced?(zipper, pipeline_name) or
        protection_for_resource?(zipper, resource_path)
    end

    defp pipeline_referenced?(zipper, pipeline_name) do
      found?(
        Function.move_to_function_call(
          zipper,
          :pipe_through,
          1,
          &Function.argument_equals?(&1, 0, pipeline_name)
        )
      )
    end

    defp protection_for_resource?(zipper, resource_path) do
      found?(
        Function.move_to_function_call(zipper, :plug, 2, fn plug ->
          Function.argument_equals?(plug, 0, ProtectResource) and
            Function.argument_matches_predicate?(plug, 1, fn opts ->
              keyword_value_equals?(opts, :resource_path, resource_path)
            end)
        end)
      )
    end

    defp keyword_value_equals?(opts, key, expected) do
      case CodeKeyword.get_key(opts, key) do
        {:ok, value} -> Common.nodes_equal?(value, expected)
        :error -> false
      end
    end

    defp keyword_literal_equals?(opts, key, expected) do
      with {:ok, value} <- CodeKeyword.get_key(opts, key),
           {:ok, actual} <- Common.expand_literal(value) do
        actual == expected
      else
        _ -> false
      end
    end

    defp legacy_metadata_route?(zipper) do
      found?(
        Function.move_to_function_call(zipper, :get, [3, 4], fn route ->
          Function.argument_equals?(route, 1, AttestoMCP.MetadataController)
        end)
      )
    end

    defp implicit_root_declaration?(zipper) do
      found?(
        Function.move_to_function_call(
          zipper,
          :attesto_mcp_protected_resource_metadata,
          [1, 2],
          &implicit_root?/1
        )
      )
    end

    defp implicit_root?(declaration) do
      Function.function_call?(declaration, :attesto_mcp_protected_resource_metadata, 1) or
        Function.argument_matches_predicate?(declaration, 1, fn opts ->
          not explicit_root?(opts)
        end)
    end

    defp non_literal_metadata_declaration?(zipper) do
      found?(
        Function.move_to_function_call(
          zipper,
          :attesto_mcp_protected_resource_metadata,
          [1, 2],
          fn declaration ->
            Function.argument_matches_predicate?(
              declaration,
              0,
              &(not CodeString.string?(&1))
            )
          end
        )
      )
    end

    defp found?({:ok, _zipper}), do: true
    defp found?(_result), do: false

    defp legacy_route_issue(resource_path) do
      """
      attesto_mcp.install found legacy raw AttestoMCP.MetadataController routes before installing
      #{inspect(resource_path)}, so no router changes were made. Replace the legacy raw `get`
      routes with `use AttestoMCP.Router` and one
      `attesto_mcp_protected_resource_metadata/2` declaration per resource. Set `root: false`
      on every resource (or explicitly set `root: true` on exactly one), and add matching
      `resource_path: <path>` plus `resource_audience: :resource` options to each ProtectResource
      pipeline. Then rerun the installer.
      """
    end

    defp implicit_root_issue(resource_path) do
      """
      attesto_mcp.install found an existing protected-resource metadata declaration with an
      implicit single-resource root before installing #{inspect(resource_path)}, so no router
      changes were made. First make root ownership explicit on the existing declaration:
      use `root: false` for no shared root, or `root: true` for the one resource that should own
      it. Then rerun the installer.
      """
    end

    defp non_literal_metadata_issue(resource_path) do
      """
      attesto_mcp.install found an existing protected-resource metadata declaration whose
      resource path is not a literal string while installing #{inspect(resource_path)}, so it
      cannot safely determine whether that declaration already owns the target route. No router
      changes were made. Replace the declaration's module attribute or other expression with a
      literal path, then rerun the installer; alternatively complete the resource wiring manually.
      """
    end

    defp partial_installation_issue(resource_path, scopes, config_mfa, base_url) do
      """
      attesto_mcp.install found existing wiring for #{inspect(resource_path)}, but it does not
      match a complete audience-confined scaffold for scopes #{inspect(scopes)}, so no router
      changes were made. Ensure the metadata declaration uses those scopes and an explicit
      boolean `root` option, `config: #{inspect(config_mfa)}`, and
      `base_url: #{inspect(base_url)}`; its ProtectResource pipeline must use the same scopes plus
      `config: #{inspect(config_mfa)}`, `base_url: #{inspect(base_url)}`,
      `resource_path: #{inspect(resource_path)}` and `resource_audience: :resource`, and the resource
      scope pipes through that pipeline. Alternatively remove the partial wiring and rerun the
      installer.
      """
    end

    # The public metadata macro is imported exactly once, immediately after the
    # router's own `use` declaration when possible, so every generated scope can
    # expand it regardless of where Igniter inserts that scope.
    defp ensure_router_use(igniter, router) do
      ProjectModule.find_and_update_module!(igniter, router, fn zipper ->
        case CodeModule.move_to_use(zipper, AttestoMCP.Router) do
          {:ok, _present} ->
            {:ok, zipper}

          :error ->
            {:ok, add_router_use(igniter, zipper)}
        end
      end)
    end

    defp add_router_use(igniter, zipper) do
      case Phoenix.move_to_router_use(igniter, zipper) do
        {:ok, router_use} ->
          Common.add_code(router_use, "use AttestoMCP.Router")

        :error ->
          Common.add_code(zipper, "use AttestoMCP.Router", placement: :before)
      end
    end

    defp config_mfa(options) do
      module_name = options[:config_module]
      function_name = options[:config_function] || "config"

      cond do
        not is_binary(module_name) or module_name == "" ->
          {:error,
           "attesto_mcp.install requires --config-module, for example " <>
             "`--config-module MyApp.Attesto`"}

        not Regex.match?(~r/\A[A-Z][A-Za-z0-9_]*(?:\.[A-Z][A-Za-z0-9_]*)*\z/, module_name) ->
          {:error, "--config-module must be a valid Elixir module name such as MyApp.Attesto"}

        not is_binary(function_name) or
            not Regex.match?(~r/\A[a-z_][A-Za-z0-9_]*[!?]?\z/, function_name) ->
          {:error, "--config-function must be a valid existing Elixir function name"}

        true ->
          existing_function_atom(module_name, function_name)
      end
    end

    defp base_url(options) do
      case options[:base_url] do
        nil ->
          {:error,
           "attesto_mcp.install requires --base-url, for example " <>
             "`--base-url https://mcp.example.com`"}

        base_url when is_binary(base_url) ->
          try do
            Metadata.validate_origin_options!(base_url: base_url)
            {:ok, String.trim_trailing(base_url, "/")}
          rescue
            ArgumentError ->
              {:error, "--base-url must be an absolute HTTPS origin without userinfo, query, or fragment"}
          end
      end
    end

    defp existing_function_atom(module_name, function_name) do
      function = String.to_existing_atom(function_name)
      {:ok, {ProjectModule.parse(module_name), function}}
    rescue
      ArgumentError ->
        {:error,
         "--config-function #{inspect(function_name)} is not an existing function atom; " <>
           "compile the configuration module before running the installer"}
    end

    defp resolve_router(igniter, options) do
      case options[:router] do
        nil ->
          case Phoenix.select_router(igniter) do
            {_igniter, nil} -> Mix.raise("No Phoenix router found")
            {_igniter, router} -> router
          end

        router ->
          Igniter.Project.Module.parse(router)
      end
    end

    # RFC 9728 Section 3.1 keys metadata off a non-empty plain resource path.
    # Validate before Igniter edits anything so a typo cannot widen the protected
    # scope to `/` or generate an unreachable well-known route.
    defp normalize_resource_path(path) do
      Metadata.normalize_resource_path!(path, allow_root: false)
    rescue
      ArgumentError ->
        Mix.raise("--resource-path must be a plain non-root path without dot segments, query, or fragment")
    end

    defp parse_scopes!(scopes) do
      parsed =
        scopes
        |> String.split(",", trim: true)
        |> Enum.map(&String.trim/1)
        |> Enum.reject(&(&1 == ""))

      if parsed == [] do
        Mix.raise("--scopes must contain at least one OAuth scope")
      end

      parsed
    end

    # Derive a stable, bounded pipeline atom. The readable slug is not unique
    # (`/mcp/foo-bar` and `/mcp/foo/bar` both normalize alike), so include a
    # SHA-256 suffix to keep distinct resources on collision-resistant names.
    defp pipeline_name(resource_path) do
      slug =
        resource_path
        |> String.replace(~r/[^a-zA-Z0-9]+/, "_")
        |> String.trim("_")
        |> String.slice(0, 40)

      slug = if slug == "", do: "resource", else: slug

      digest =
        :sha256
        |> :crypto.hash(resource_path)
        |> Base.encode16(case: :lower)

      :"mcp_protected_#{slug}_#{digest}"
    end
  end
else
  defmodule Mix.Tasks.AttestoMcp.Install do
    @shortdoc "#{Mix.Tasks.AttestoMcp.Install.Docs.short_doc()} | Install `igniter` to use"

    @moduledoc Mix.Tasks.AttestoMcp.Install.Docs.long_doc()

    use Mix.Task

    @impl Mix.Task
    def run(_argv) do
      Mix.shell().error("""
      The task 'attesto_mcp.install' requires igniter. Install `igniter` and run it with:

          mix igniter.install attesto_mcp

      or add `{:igniter, ">= 0.6.0 and < 0.8.1 or >= 0.8.4 and < 1.0.0"}` to your deps and run
      `mix attesto_mcp.install` again.
      """)

      exit({:shutdown, 1})
    end
  end
end
