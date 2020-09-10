defmodule KittenBlue.JWK do
  @moduledoc """
  Structure containing `kid`, `alg`, `JOSE.JWK` and handling functions
  """

  require Logger

  defstruct [
    :kid,
    :alg,
    :key
  ]

  @type t :: %__MODULE__{kid: String.t(), alg: String.t(), key: JOSE.JWK.t()}

  @http_client Application.fetch_env!(:kitten_blue, __MODULE__) |> Keyword.fetch!(:http_client)

  # NOTE: from_compact/to_conpact does not support Poly1305
  @algs_for_oct ["HS256", "HS384", "HS512"]
  @algs_for_pem [
    "ES256",
    "ES384",
    "ES512",
    "Ed25519ph",
    "Ed448",
    "Ed448ph",
    "PS256",
    "PS384",
    "PS512",
    "RS256",
    "RS384",
    "RS512"
  ]

  @doc """
  ```Elixir
  kid = "sample_201804"
  alg = "RS256"
  key = JOSE.JWK.from_pem_file("rsa-2048.pem")

  kb_jwk = KittenBlue.JWK.new([kid, alg, key])
  kb_jwk = KittenBlue.JWK.new([kid: kid, alg: alg, key: key])
  kb_jwk = KittenBlue.JWK.new(%{kid: kid, alg: alg, key: key})
  ```
  """
  @spec new(params :: Keywords.t()) :: t
  def new(params = [kid: _, alg: _, key: _]) do
    struct(__MODULE__, Map.new(params))
  end

  @spec new(params :: List.t()) :: t
  def new([kid, alg, key]) do
    struct(__MODULE__, %{kid: kid, alg: alg, key: key})
  end

  @spec new(params :: Map.t()) :: t
  def new(params = %{kid: _, alg: _, key: _}) do
    struct(__MODULE__, params)
  end

  @doc """
  Convert `KittenBlue.JWK` list to `JSON Web Key Sets` format public keys.

  ```Elixir
  kb_jwk_list = [kb_jwk]
  public_jwk_sets = KittenBlue.JWK.list_to_public_jwk_sets(kb_jwk_list)
  ```
  """
  @spec list_to_public_jwk_sets(jwk_list :: List.t()) :: map | nil
  def list_to_public_jwk_sets([]) do
    nil
  end

  def list_to_public_jwk_sets(jwk_list) when is_list(jwk_list) do
    %{
      "keys" =>
        jwk_list
        |> Enum.map(fn jwk -> to_public_jwk_set(jwk) end)
        |> Enum.filter(&(!is_nil(&1)))
    }
  end

  @doc """
  Convert `KittenBlue.JWK` to `JSON Web Key Sets` format public key.

  ```Elixir
  public_jwk_set = KittenBlue.JWK.to_public_jwk_set(kb_jwk)
  ```
  """
  @spec to_public_jwk_set(jwk :: t) :: map | nil
  def to_public_jwk_set(jwk = %__MODULE__{}) do
    jwk.key
    |> JOSE.JWK.to_public()
    |> JOSE.JWK.to_map()
    |> elem(1)
    |> Map.put("alg", jwk.alg)
    |> Map.put("kid", jwk.kid)
  end

  def to_public_jwk_set(_) do
    nil
  end

  @doc """
  Convert `JSON Web Key Sets` format public keys to `KittenBlue.JWK` list.

  ```
  kb_jwk_list = KittenBlue.JWK.public_jwk_sets_to_list(public_jwk_sets)
  ```
  """
  @spec public_jwk_sets_to_list(public_json_web_key_sets :: map) :: List.t()
  def public_jwk_sets_to_list(_public_json_web_key_sets = %{"keys" => public_jwk_sets})
      when is_list(public_jwk_sets) do
    public_jwk_sets
    |> Enum.map(fn public_jwk_set -> from_public_jwk_set(public_jwk_set) end)
    |> Enum.filter(&(!is_nil(&1)))
  end

  def public_jwk_sets_to_list(_public_json_web_key_sets) do
    []
  end

  @doc """
  Convert `JSON Web Key Sets` format public key to `KittenBlue.JWK`.

  ```
  kb_jwk = KittenBlue.JWK.from_public_jwk_set(public_jwk_set)
  ```
  """
  @spec from_public_jwk_set(public_json_web_key_set :: map) :: t | nil
  def from_public_jwk_set(jwk_map) when is_map(jwk_map) do
    try do
      with alg when alg != nil <- jwk_map["alg"],
           kid when kid != nil <- jwk_map["kid"],
           key = %JOSE.JWK{} <- jwk_map |> JOSE.JWK.from_map() do
        new(kid: kid, alg: alg, key: key)
      else
        _ -> nil
      end
    rescue
      _ -> nil
    end
  end

  def from_public_jwk_set(_) do
    nil
  end

  @doc """
  Convert `KittenBlue.JWK` List to compact storable format for configration.

  ```
  kb_jwk_list = [kb_jwk]
  kb_jwk_list_config = KittenBlue.JWK.list_to_compact(kb_jwk_list)
  ```
  """
  @spec list_to_compact(jwk_list :: List.t()) :: List.t()
  def list_to_compact(jwk_list) do
    jwk_list
    |> Enum.map(fn jwk -> to_compact(jwk) end)
  end

  @doc """
  Convert `KittenBlue.JWK` to compact storable format for configration.

  ```
  kb_jwk_config = KittenBlue.JWK.to_compact(kb_jwk)
  ```
  """
  @spec to_compact(jwk :: t(), opts :: Keyword.t()) :: List.t()
  def to_compact(jwk, opts \\ []) do
    case {jwk.alg, opts[:use_map]} do
      {_, true} ->
        [jwk.kid, jwk.alg, jwk.key |> JOSE.JWK.to_map() |> elem(1)]

      {alg, _} when alg in @algs_for_oct ->
        [
          jwk.kid,
          jwk.alg,
          jwk.key |> JOSE.JWK.to_oct() |> elem(1) |> Base.encode64(padding: false)
        ]

      {alg, _} when alg in @algs_for_pem ->
        [jwk.kid, jwk.alg, jwk.key |> JOSE.JWK.to_pem() |> elem(1)]

      {_, _} ->
        []
    end
  end

  @doc """
  Convert compact storable format to `KittenBlue.JWK`.

  ```
  kb_jwk_list = KittenBlue.JWK.compact_to_list(kb_jwk_list_config)
  ```
  """
  @spec compact_to_list(jwk_compact_list :: list()) :: t()
  def compact_to_list(jwk_compact_list) when is_list(jwk_compact_list) do
    jwk_compact_list
    |> Enum.map(fn jwk_compact -> from_compact(jwk_compact) end)
    |> Enum.filter(&(!is_nil(&1)))
  end

  @doc """
  Convert compact storable format to `KittenBlue.JWK`.

  ```
  kb_jwk = KittenBlue.JWK.from_compact(kb_jwk_config)
  ```
  """
  @spec from_compact(jwk_compact :: list()) :: t() | nil
  def from_compact(_jwk_compact = [kid, alg, key]) do
    cond do
      is_map(key) ->
        [kid, alg, key |> JOSE.JWK.from_map()] |> new()

      alg in @algs_for_oct ->
        [kid, alg, key |> Base.decode64!(padding: false) |> JOSE.JWK.from_oct()] |> new()

      alg in @algs_for_pem ->
        [kid, alg, key |> JOSE.JWK.from_pem()] |> new()

      true ->
        nil
    end
  end

  @doc """
  Fetch jwks uri and return jwk list.

  ```
  kb_jwk_list = KittenBlue.JWK.fetch!(jwks_uri)
  ```
  """
  @spec fetch!(jwks_uri :: String.t()) :: [t()] | nil
  def fetch!(jwks_uri) do
    case @http_client.get(jwks_uri) do
      {:ok, %HTTPoison.Response{status_code: 200, body: body}} ->
        Jason.decode!(body) |> __MODULE__.public_jwk_sets_to_list()

      {:ok, %HTTPoison.Response{} = res} ->
        Logger.warn("HTTPoison.get returned {:ok, #{inspect(res)}}")
        nil

      {:error, %HTTPoison.Error{} = error} ->
        Logger.warn("HTTPoison.get returned {:error, #{inspect(error)}}")
        nil
    end
  end
end
