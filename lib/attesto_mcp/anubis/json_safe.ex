defmodule AttestoMCP.Anubis.JSONSafe do
  @moduledoc """
  Produce a JSON-safe copy of an MCP session-state map before it is written to a
  `jsonb` column.

  Anubis folds the whole request `conn.assigns` into the persisted session
  `frame`, so the state map an `Anubis.Server.Session.Store` is handed can carry
  values the configured Postgrex JSON library cannot encode - a request-scoped struct
  (e.g. a host's authenticated-user struct), a tuple, a pid, a ref, a function,
  a `MapSet`. Encoding such a map raises in the database driver, which - because
  it happens mid-`initialize` - would crash the session process and drop the
  connection.

  `sanitize/1` recursively drops anything non-encodable from its enclosing map
  or list while preserving encodable siblings:

    * a struct accepted by the configured JSON library is converted to JSON
      primitives; a rejected struct is dropped;
    * a map keeps only entries whose key is a valid JSON object key (binary or
      atom) **and** whose value survives sanitization;
    * a list keeps only its surviving elements.

  Keys are otherwise preserved as-is, so a string-keyed restore reads the same
  values back after the `jsonb` round-trip. The result always encodes cleanly.
  """

  # Out-of-band drop sentinel. A two-element module tuple is itself never a kept
  # (JSON-safe) value, so it cannot collide with a legitimate sanitized value the
  # way a bare atom sentinel could (a real `:__drop__` in the input would then be
  # wrongly filtered).
  @drop {__MODULE__, :__drop__}

  @doc """
  Return a JSON-encodable copy of `value`, dropping any non-encodable members.

  A top-level value that is itself non-encodable (and not a map or list to
  descend into) sanitizes to an empty map, so the return is always encodable.
  """
  @spec sanitize(term(), module()) :: term()
  def sanitize(value, json_library \\ default_json_library()) when is_atom(json_library) do
    sanitized =
      case safe(value, json_library) do
        @drop -> %{}
        value -> value
      end

    case encode(json_library, sanitized) do
      {:ok, _iodata} -> sanitized
      :error -> %{}
    end
  end

  defp safe(%_{} = struct, json_library) do
    with {:ok, encoded} <- encode(json_library, struct),
         {:ok, decoded} <- decode(json_library, encoded) do
      safe(decoded, json_library)
    else
      _ -> @drop
    end
  end

  defp safe(map, json_library) when is_map(map) do
    Map.new(
      for {k, v} <- map,
          json_key?(k),
          (sv = safe(v, json_library)) != @drop,
          do: {k, sv}
    )
  end

  # A non-empty keyword list cannot be encoded as a JSON value (it is a list of
  # tuples), but it carries data the caller meant to keep. Convert it to an
  # object rather than silently collapsing every entry to `[]`. An empty list is
  # a valid JSON array and stays one.
  defp safe([], _json_library), do: []

  defp safe([_ | _] = list, json_library) do
    if proper_list?(list) do
      if Keyword.keyword?(list),
        do: safe(Map.new(list), json_library),
        else: sanitize_list(list, json_library)
    else
      @drop
    end
  end

  # A binary is kept only when it is valid UTF-8: `is_binary/1` admits arbitrary
  # byte sequences, but the JSON encoder rejects invalid UTF-8 and would raise on
  # the insert. A non-byte-aligned bitstring is never JSON-encodable, so drop it.
  defp safe(value, _json_library) when is_binary(value) do
    if valid_json_string?(value), do: value, else: @drop
  end

  defp safe(value, _json_library) when is_bitstring(value), do: @drop

  defp safe(value, json_library), do: json_round_trip(value, json_library)

  defp sanitize_list(list, json_library), do: for(v <- list, (sv = safe(v, json_library)) != @drop, do: sv)

  # A binary key is kept only when it is valid UTF-8 (see `safe/1` for binaries);
  # an atom key encodes to its name. Any other key (integer, tuple, ...) cannot
  # be a JSON object key and its entry is dropped.
  defp json_key?(key) when is_atom(key), do: key |> Atom.to_string() |> valid_json_string?()
  defp json_key?(key) when is_binary(key), do: valid_json_string?(key)
  defp json_key?(_key), do: false

  defp valid_json_string?(value), do: String.valid?(value) and not String.contains?(value, <<0>>)

  defp proper_list?(list) do
    _ = length(list)
    true
  rescue
    ArgumentError -> false
  end

  defp json_round_trip(value, json_library) do
    with {:ok, encoded} <- encode(json_library, value),
         {:ok, decoded} <- decode(json_library, encoded) do
      decoded
    else
      _ -> @drop
    end
  end

  defp encode(json_library, value) do
    {:ok, json_library.encode_to_iodata!(value)}
  rescue
    _exception -> :error
  catch
    _kind, _reason -> :error
  end

  defp decode(json_library, encoded) do
    {:ok, json_library.decode!(IO.iodata_to_binary(encoded))}
  rescue
    _exception -> :error
  catch
    _kind, _reason -> :error
  end

  defp default_json_library, do: Application.get_env(:postgrex, :json_library, Jason)
end
