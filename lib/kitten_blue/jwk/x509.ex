defmodule KittenBlue.JWK.X509 do
  @moduledoc """
  Handling JWK modules with regard to X.509
  """

  @type certificate :: X509.ASN1.record(:otp_certificate)

  @doc """
  Generate KittenBlue.JWK from JWS Token that includes X.509 Certificate Chain
  """
  @spec new_from_jws_token(jws_token :: String.t(), trusted_cert :: certificate()) ::
          KittenBlue.JWK.t()
          | {:error, :invalid_certificate}
          | {:error, :invalid_jws_header}
          | {:error, :invalid_jws_format}
  def new_from_jws_token(jws_token, trusted_cert) do
    try do
      JOSE.JWS.peek_protected(jws_token)
      |> Jason.decode!()
      |> case do
        %{"kid" => kid, "alg" => alg, "x5c" => x5c} ->
          cert_chain = x5c |> Enum.map(&Base.decode64!/1) |> Enum.reverse()

          case :public_key.pkix_path_validation(trusted_cert, cert_chain, []) do
            {:ok, {{_, key, _}, _}} ->
              [kid, alg, key |> JOSE.JWK.from_key()] |> KittenBlue.JWK.new()

            _ ->
              {:error, :invalid_certificate}
          end
        _ ->
          {:error, :invalid_jws_header}
      end
    rescue
      _ ->
        {:error, :invalid_jws_format}
    end
  end
end
