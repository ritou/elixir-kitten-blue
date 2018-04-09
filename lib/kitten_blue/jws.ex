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
  ```
  """
  @spec verify(token :: String.t(), keys :: List.t()) ::
          {:error, :invalid_jwt_format}
          | {:error, :invalid_jwt_kid}
          | {:error, :invalid_jwt_signature}
          | {:ok, payload :: map}
  def verify(token, keys) when is_binary(token) and is_list(keys) do
    with {:ok, jwk} <- validate_jwt_header(token, keys),
         {:ok, payload} <- validate_jwt_signature(token, jwk) do
      {:ok, payload}
    else
      _ = e -> e
    end
  end

  @spec validate_jwt_header(token :: String.t(), keys :: List.t()) ::
          {:error, :invalid_jwt_format}
          | {:ok, jwk :: KittenBlue.JWK.t()}
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

  @spec validate_jwt_signature(token :: String.t(), jwk :: KittenBlue.JWK.t()) ::
          {:error, :invalid_jwt_signature}
          | {:ok, payload :: map}
  defp validate_jwt_signature(token, jwk) do
    case JOSE.JWT.verify_strict(jwk.key, [jwk.alg], token) do
      {true, %JOSE.JWT{fields: payload}, _} -> {:ok, payload}
      _ -> {:error, :invalid_jwt_signature}
    end
  end

  @doc """
  Sign payload with `KittenBlue.JWK`

  ```
  {:ok, token} = KittenBlue.JWS.sign(payload, kb_jwk)
  ```
  """
  @spec sign(payload :: map, key :: KittenBlue.JWK.t()) ::
          {:ok, String.t()} | {:error, :invalid_key}
  def sign(payload, key = %KittenBlue.JWK{}) do
    token =
      key.key
      |> JOSE.JWT.sign(%{"alg" => key.alg, "kid" => key.kid}, payload)
      |> JOSE.JWS.compact()
      |> elem(1)

    {:ok, token}
  end

  def sign(_, _) do
    {:error, :invalid_key}
  end
end
