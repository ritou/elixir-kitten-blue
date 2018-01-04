defmodule KittenBlue.JWK do
  @moduledoc """
  Structure containing `kid`, `alg`, `JOSE.JWK` and handling functions
  """

  defstruct [
    :kid,
    :alg,
    :key
  ]

  @type t :: %__MODULE__{kid: String.t, alg: String.t, key: JOSE.JWK.t}

  @doc """
  ```
  kb_jwk = KittenBlue.JWK.new([kid: kid, alg: alg, key: key])
  ```
  """
  @spec new(opts :: Keywords.t) :: t
  def new(opts) do
    struct(__MODULE__, Map.new(opts))
  end

  @doc """
  Convert `KittenBlue.JWK` list to `JSON Web Key Sets` format public keys.

  ```
  public_jwk_sets = KittenBlue.JWK.list_to_public_jwk_sets(jwk_list)
  ```
  """
  @spec list_to_public_jwk_sets(jwk_list :: List.t) :: map
  def list_to_public_jwk_sets(jwk_list) when is_list(jwk_list) do
    %{"keys" =>
      jwk_list
      |> Enum.map(fn(jwk) -> to_public_key_map(jwk) end)
      |> Enum.filter(& !is_nil(&1))
    }
  end

  defp to_public_key_map(jwk = %__MODULE__{}) do
    jwk.key
    |> JOSE.JWK.to_public()
    |> JOSE.JWK.to_map()
    |> elem(1)
    |> Map.put("alg", jwk.alg)
    |> Map.put("kid", jwk.kid)
  end
  defp to_public_key_map(_) do
    nil
  end

  @doc """
  Convert `JSON Web Key Sets` format public keys to `KittenBlue.JWK`.

  ```
  jwk_list = KittenBlue.JWK.public_jwk_sets_to_list(public_jwk_sets)
  ```
  """
  @spec public_jwk_sets_to_list(public_json_web_key_sets :: map) :: List.t
  def public_jwk_sets_to_list(_ = %{"keys" => public_jwk_sets}) when is_list(public_jwk_sets) do
    public_jwk_sets
    |> Enum.map(fn(public_jwk_set) -> from_public_key_map(public_jwk_set) end)
    |> Enum.filter(& !is_nil(&1))
  end
  def public_jwk_sets_to_list(_) do
    []
  end

  defp from_public_key_map(jwk_map) when is_map(jwk_map) do
    try do
      with alg when alg != nil <- jwk_map["alg"],
           kid when kid != nil <- jwk_map["kid"],
           key = %JOSE.JWK{} <- jwk_map |> JOSE.JWK.from_map() do
        new([kid: kid, alg: alg, key: key])
      else
        _ -> nil
      end
    rescue
      _ -> nil
    end
  end
  defp from_public_key_map(_) do
    nil
  end
end
