defmodule KittenBlue.JWS.DPoP do
  @moduledoc """
  This module is a helper module that supports the generation and verification of DPoP Proof JWT as defined in RFC9449.
  """

  alias KittenBlue.{JWK, JWS}

  @typ "dpop+jwt"

  @dpop_fixed_kid "dpop-kid"

  @default_alg "ES256"

  @doc """
  Function to return the private key for a given algorithm

  NOTE: move to KittenBlue.JWK
  """
  @spec generate_private_key(opts :: Keyword.t()) :: {:ok, jwk :: JWK} | {:error, term}
  def generate_private_key(opts \\ []) do
    with alg <- Keyword.get(opts, :alg, @default_alg),
         key = %JOSE.JWK{} <- JOSE.JWS.generate_key(%{"alg" => alg}),
         kid <- Keyword.get(opts, :kid, UUID.uuid4()),
         jwk <- JWK.new([kid, alg, key]) do
      {:ok, jwk}
    end
  end

  @doc """
  Function to create DPoP Proof JWT

  ref. https://datatracker.ietf.org/doc/html/rfc9449#section-4.2
  """
  @spec issue_dpop_proof_jwt(payload :: map, jwk :: JWK.t()) ::
          {:ok, jwt :: String.t()} | {:error, term}
  def issue_dpop_proof_jwt(payload, jwk = %JWK{}) do
    with :ok <- validate_payload(payload),
         {:ok, header} <- create_header(jwk),
         {:ok, jwt} <- JWS.sign(payload, jwk, header, ignore_kid: true) do
      {:ok, jwt}
    end
  end

  @doc """
  Function to verify DPoP Proof JWT's payload and signature

  ref. https://datatracker.ietf.org/doc/html/rfc9449#section-4.3
  """
  @spec verify_dpop_proof_jwt(jwt :: String.t()) ::
          {:ok, header :: map, payload :: map} | {:error, term}
  def verify_dpop_proof_jwt(jwt) do
    with {:ok, payload} <- JOSE.JWS.peek_payload(jwt) |> Jason.decode(),
         :ok <- validate_payload(payload),
         {:ok, header} <- JOSE.JWS.peek_protected(jwt) |> Jason.decode(),
         {:ok, key} <- validate_header(header),
         {:ok, _} <- JWS.verify_without_kid(jwt, key) do
      {:ok, payload}
    end
  end

  defp validate_payload(%{"jti" => _, "htm" => _, "htu" => _, "iat" => _, "ath" => _}), do: :ok
  defp validate_payload(%{"jti" => _, "htm" => _, "htu" => _, "iat" => _}), do: :ok
  defp validate_payload(_), do: {:error, :invalid_payload}

  defp create_header(jwk) do
    with pubkey <- JWK.to_public_jwk_set(jwk) |> Map.drop(["alg", "kid", "use"]) do
      {:ok, %{"typ" => @typ, "alg" => jwk.alg, "jwk" => pubkey}}
    end
  end

  defp validate_header(%{"typ" => @typ, "alg" => alg, "jwk" => public_key_params}) do
    with jwk = %JWK{} <-
           JWK.from_public_jwk_set(
             public_key_params
             |> Map.merge(%{"kid" => @dpop_fixed_kid, "alg" => alg})
           ) do
      {:ok, jwk}
    end
  end

  defp validate_header(_), do: {:error, :invalid_header}
end
