defmodule KittenBlue.JWK.X509 do
  @moduledoc """
  Handling JWK modules with regard to X.509
  """

  defstruct [
    :x5c
  ]

  @type t :: %__MODULE__{x5c: [String.t()]}

  @type certificate :: X509.ASN1.record(:otp_certificate)

  @doc """
  Generate KittenBlue.JWK.X509 struct

  ```Elixir
  kid = "sample_202301"
  alg = "RS256"
  key = JOSE.JWK.from_pem_file("rsa-2048.pem")

  x5c = [cert |> X509.Certificate.to_der() |> Base.encode64()]
  x509 = KittenBlue.JWK.X509.new([x5c: x5c])
  kb_jwk = KittenBlue.JWK.new(%{kid: kid, alg: alg, key: key, x509: x509})
  ```
  """
  @spec new(params :: Keywords.t()) :: t
  def new(params = [x5c: _]) do
    struct(__MODULE__, Map.new(params))
  end

  @spec new(params :: Map.t()) :: t
  def new(params = %{x5c: _}) do
    struct(__MODULE__, params)
  end

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
