defmodule KittenBlue.JWS.X509Test do
  use ExUnit.Case

  alias KittenBlue.{JWK, JWS}

  describe "sign and verify" do
    test "RS256" do
      key = File.read!("sample_pem/rsa-2048.pem") |> X509.PrivateKey.from_pem!()

      root_ca =
        X509.Certificate.self_signed(
          key,
          "/C=JP/ST=Tokyo/L=Shibuya/O=Acme/CN=Root CA",
          template: :root_ca
        )

      cert =
        key
        |> X509.PublicKey.derive()
        |> X509.Certificate.new(
          "/C=JP/ST=Tokyo/L=Shibuya/O=Acme/CN=Cert",
          root_ca,
          key
        )

      x5c = [cert |> X509.Certificate.to_der() |> Base.encode64()]

      alg = "RS256"
      kid = "rs256_202301"

      jwk =
        %{
          kid: kid,
          alg: alg,
          key: key |> JOSE.JWK.from_key(),
          x509: JWK.X509.new(x5c: x5c)
        }
        |> JWK.new()

      payload = %{"key" => "value"}

      assert {:ok, jws} = JWS.sign(payload, jwk)

      assert jwk = JWK.X509.new_from_jws_token(jws, root_ca)

      assert {:ok, payload} == JWS.verify(jws, [jwk])
    end
  end
end
