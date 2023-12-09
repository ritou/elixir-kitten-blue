defmodule KittenBlue.JWS do
  @moduledoc """
  This module provides `JOSE.JWS` wrappter functions using `KittenBlue.JWK`

  * verify : Signature verification using `KittenBlue.JWK` list.
  * sign : Sign payload with `KittenBlue.JWK`
  """

  @doc """
  Signature verification using `KittenBlue.JWK` list.

  ```
  {:ok, payload} = KittenBlue.JWS.verify(token, kb_jwk_list)

  # with header param
  {:ok, payload} = KittenBlue.JWS.verify(token, kb_jwk_list, %{"typ" => "my_jwt_usage"})
  ```
  """
  @spec verify(token :: String.t(), keys :: List.t(), required_header :: map) ::
          {:error, :invalid_jwt_format}
          | {:error, :invalid_jwt_kid}
          | {:error, :invalid_jwt_signature}
          | {:error, :invalid_jwt_header}
          | {:ok, payload :: map}
  def verify(token, keys, required_header \\ nil) when is_binary(token) and is_list(keys) do
    with {:ok, jwk} <- validate_jwt_header(token, keys),
         {:ok, payload} <- validate_jwt_signature(token, jwk, required_header) do
      {:ok, payload}
    end
  end

  @spec verify_without_kid(token :: String.t(), key :: KittenBlue.JWK.t(), required_header :: map) ::
          {:error, :invalid_jwt_format}
          | {:error, :invalid_jwt_signature}
          | {:error, :invalid_jwt_header}
          | {:ok, payload :: map}
  def verify_without_kid(token, key = %KittenBlue.JWK{}, required_header \\ nil)
      when is_binary(token) do
    with {:ok, nil} <- validate_jwt_header(token, nil),
         {:ok, payload} <- validate_jwt_signature(token, key, required_header) do
      {:ok, payload}
    end
  end

  @spec validate_jwt_header(token :: String.t(), keys :: List.t() | nil) ::
          {:error, :invalid_jwt_format}
          | {:ok, jwk :: KittenBlue.JWK.t()}
  defp validate_jwt_header(token, nil) do
    try do
      JOSE.JWT.peek_protected(token)
      |> case do
        %JOSE.JWS{fields: %{}} -> {:ok, nil}
        _ -> {:error, :invalid_jwt_format}
      end
    rescue
      _ -> {:error, :invalid_jwt_format}
    end
  end

  defp validate_jwt_header(token, keys) do
    try do
      JOSE.JWT.peek_protected(token)
      |> case do
        %JOSE.JWS{fields: %{"kid" => kid}} -> load_jwk(keys, kid)
        _ -> {:error, :invalid_jwt_format}
      end
    rescue
      _ -> {:error, :invalid_jwt_format}
    end
  end

  @spec load_jwk(keys :: List.t(), kid :: String.t()) ::
          {:error, :invalid_jwt_kid}
          | {:ok, jwk :: KittenBlue.JWK.t()}
  defp load_jwk(keys, kid) do
    keys
    |> Enum.find(fn kb_jwk -> kb_jwk.kid == kid end)
    |> case do
      nil -> {:error, :invalid_jwt_kid}
      kb_jwk -> {:ok, kb_jwk}
    end
  end

  @spec validate_jwt_signature(
          token :: String.t(),
          jwk :: KittenBlue.JWK.t(),
          required_header :: map
        ) ::
          {:error, :invalid_jwt_signature}
          | {:error, :invalid_jwt_header}
          | {:ok, payload :: map}
  defp validate_jwt_signature(token, jwk, required_header) do
    case JOSE.JWT.verify_strict(jwk.key, [jwk.alg], token) do
      {true, %JOSE.JWT{fields: payload}, %JOSE.JWS{fields: header}} ->
        if is_nil(required_header) do
          {:ok, payload}
        else
          if Map.equal?(header, Map.merge(header, required_header)) do
            {:ok, payload}
          else
            {:error, :invalid_jwt_header}
          end
        end

      _ ->
        {:error, :invalid_jwt_signature}
    end
  end

  @doc """
  Sign payload with `KittenBlue.JWK`

  ```
  {:ok, token} = KittenBlue.JWS.sign(payload, kb_jwk)

  # use header param
  {:ok, token} = KittenBlue.JWS.sign(payload, kb_jwk, %{"typ" => "my_jwt_usage"})
  ```
  """
  @spec sign(payload :: map, key :: KittenBlue.JWK.t(), header :: map, opts :: Keyword.t()) ::
          {:ok, String.t()} | {:error, :invalid_key}
  def sign(payload, key, header \\ %{}, opts \\ [])

  def sign(payload, %KittenBlue.JWK{x509: %KittenBlue.JWK.X509{} = x509} = key, header, opts) do
    additional_header_params =
      if opts[:ignore_kid],
        do: %{"alg" => key.alg, "x5c" => x509.x5c},
        else: %{"alg" => key.alg, "kid" => key.kid, "x5c" => x509.x5c}

    token =
      key.key
      |> JOSE.JWS.sign(
        payload |> Jason.encode!(),
        header |> Map.merge(additional_header_params)
      )
      |> JOSE.JWS.compact()
      |> elem(1)

    {:ok, token}
  end

  def sign(payload, %KittenBlue.JWK{} = key, header, opts) do
    additional_header_params =
      if opts[:ignore_kid], do: %{"alg" => key.alg}, else: %{"alg" => key.alg, "kid" => key.kid}

    token =
      key.key
      |> JOSE.JWT.sign(Map.merge(header, additional_header_params), payload)
      |> JOSE.JWS.compact()
      |> elem(1)

    {:ok, token}
  end

  def sign(_, _, _, _) do
    {:error, :invalid_key}
  end
end
