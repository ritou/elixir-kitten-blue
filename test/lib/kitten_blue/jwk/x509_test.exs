defmodule KittenBlue.JWK.X509Test do
  use ExUnit.Case

  alias KittenBlue.JWK
  doctest JWK.X509

  describe "RS256 new_from_jws_token/2" do
    setup do
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

      [key: key, root_ca: root_ca, x5c: x5c]
    end

    test "ok", %{key: key, root_ca: root_ca, x5c: x5c} do
      alg = "RS256"
      kid = "rs256_202301"

      jws =
        key
        |> JOSE.JWK.from_key()
        |> JOSE.JWS.sign(
          %{"key" => "value"} |> Jason.encode!(),
          %{
            "alg" => alg,
            "kid" => kid,
            "x5c" => x5c
          }
        )
        |> JOSE.JWS.compact()
        |> elem(1)

      %JWK{} = jwk_x509 = JWK.X509.new_from_jws_token(jws, root_ca)
      compact = JWK.to_compact(jwk_x509)
      assert [^kid, ^alg, jwk_public_key] = compact

      jwk_public_key_pem = jwk_public_key |> X509.PublicKey.from_pem!() |> X509.PublicKey.to_pem()
      public_key_pem = key |> X509.PublicKey.derive() |> X509.PublicKey.to_pem()

      assert jwk_public_key_pem == public_key_pem
    end

    test "verify error: invalid_certificate", %{key: key, x5c: x5c} do
      alg = "RS256"
      kid = "rs256_202301"

      jws =
        key
        |> JOSE.JWK.from_key()
        |> JOSE.JWS.sign(
          %{"key" => "value"} |> Jason.encode!(),
          %{
            "alg" => alg,
            "kid" => kid,
            "x5c" => x5c
          }
        )
        |> JOSE.JWS.compact()
        |> elem(1)

      key_2 = X509.PrivateKey.new_rsa(512)

      root_ca_2 =
        X509.Certificate.self_signed(
          key_2,
          "/C=JP/ST=Tokyo/L=Shibuya/O=Acme/CN=Root CA",
          template: :root_ca
        )

      assert {:error, :invalid_certificate} == JWK.X509.new_from_jws_token(jws, root_ca_2)
    end

    test "verify error: invalid_jws_header", %{key: key, root_ca: root_ca, x5c: x5c} do
      alg = "RS256"

      jws =
        key
        |> JOSE.JWK.from_key()
        |> JOSE.JWS.sign(
          %{"key" => "value"} |> Jason.encode!(),
          %{
            "alg" => alg,
            "x5c" => x5c
          }
        )
        |> JOSE.JWS.compact()
        |> elem(1)

      assert {:error, :invalid_jws_header} == JWK.X509.new_from_jws_token(jws, root_ca)
    end

    test "verify error: invalid_jws_format", %{root_ca: root_ca} do
      assert {:error, :invalid_jws_format} == JWK.X509.new_from_jws_token("", root_ca)
    end
  end
end
