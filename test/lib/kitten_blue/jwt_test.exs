defmodule KittenBlue.JWTTest do
  use ExUnit.Case

  alias KittenBlue.JWT
  doctest JWT

  # The payload of OIDC ID Token
  # https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
  @sample_payload %{
    "iss" => "http://server.example.com",
    "sub" => "248289761001",
    "aud" => "s6BhdRkqt3",
    "nonce" => "n-0S6_WzA2Mj",
    "exp" => 1_311_281_970,
    "nbf" => 1_311_280_970,
    "iat" => 1_311_280_970
  }

  describe "verify_claims" do
    test "iss" do
      assert :ok == JWT.verify_claims(@sample_payload, %{"iss" => "http://server.example.com"})

      assert {:error, :invalid_payload, "iss"} ==
               JWT.verify_claims(@sample_payload, %{"iss" => "http://server.example.net"})
    end

    test "aud" do
      assert :ok == JWT.verify_claims(@sample_payload, %{"aud" => "s6BhdRkqt3"})

      assert {:error, :invalid_payload, "aud"} ==
               JWT.verify_claims(@sample_payload, %{"aud" => "s6BhdRkqt4"})

      assert :ok ==
               JWT.verify_claims(Map.merge(@sample_payload, %{"aud" => ["s6BhdRkqt3"]}), %{
                 "aud" => "s6BhdRkqt3"
               })

      assert {:error, :invalid_payload, "aud"} ==
               JWT.verify_claims(Map.merge(@sample_payload, %{"aud" => ["s6BhdRkqt3"]}), %{
                 "aud" => "s6BhdRkqt4"
               })
    end

    test "exp" do
      assert :ok == JWT.verify_claims(@sample_payload, %{"exp" => 1_311_281_969})
      assert :ok == JWT.verify_claims(@sample_payload, %{"exp" => 1_311_281_970})

      assert {:error, :invalid_payload, "exp"} ==
               JWT.verify_claims(@sample_payload, %{"exp" => 1_311_281_971})
    end

    test "nbf" do
      assert :ok == JWT.verify_claims(@sample_payload, %{"nbf" => 1_311_280_970})
      assert :ok == JWT.verify_claims(@sample_payload, %{"nbf" => 1_311_280_971})

      assert {:error, :invalid_payload, "nbf"} ==
               JWT.verify_claims(@sample_payload, %{"nbf" => 131_128_069})
    end
  end
end
