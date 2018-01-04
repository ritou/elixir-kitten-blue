defmodule KittenBlue.JWSTest do
  use ExUnit.Case

  alias KittenBlue.{JWK, JWS}
  doctest JWS

  @hs256_jwk_1 [
    kid: "hs256_first",
    alg: "HS256",
    key: "yx1dSdNR624-DZF1HdpdHeRb2Pa2AGaqF-ig8HCsPwU" |> Base.url_decode64!(padding: false) |> JOSE.JWK.from_oct()
  ] |> JWK.new()
  @hs256_jwk_2 [
    kid: "hs256_second",
    alg: "HS256",
    key: "XrjkdL7Ma6xxNmiIj0_K1UkztTakF0Dd6k1fyYjd-kI" |> Base.url_decode64!(padding: false) |> JOSE.JWK.from_oct()
  ] |> JWK.new()
  @hs256_jwk_3 [
    kid: @hs256_jwk_1.kid,
    alg: @hs256_jwk_1.alg,
    key: @hs256_jwk_2.key,
  ] |> JWK.new()

  @rs256_jwk_1 [
    kid: "rs256_first",
    alg: "RS256",
    key: ~S"""
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEAvTpKoAgqi3TtyT20ncxKkcNOOJEmOgy96Spry+AC0F+2UDFG
    JJ7shvhhEwxZy5+24H+Td5DGV1DKN0Gn2wb8dfWMH1x0HzsDEtJldFTf5GCK96QC
    U79XtwedX7p8Yvt5cDGnVCVlODhM9S7/5Ztvnm3PsE/8ZFnsLUI4zdx4qg5295x0
    oYU1zmBDAOl3y9i9vGdhmtqZ1uwVXJXTziWooV9z7Qyi3Y4+6QOgj/6p6GSFDZv9
    CYHMYZPWk6+dFmnSrOaHfA5C5W++vdlAinhn8zWxO3ROdaKklmV9doF45cq843SK
    +E+N/aYYEmTkpCrOApyI76nNrFzdrsRb+2KVUwIDAQABAoIBAB2opUmv/fsduKdy
    JH0XKBjwo7H6DiPLG3kQTRUHZ2mBlvG6x2O2BRyikZSKuwhPYDqPxG1ZI71LzGYc
    xFJwJeHXOr8vnoPGnBS3JW+2XeFNwHpQGo1F0Fm/t8rpT9Wz1LThE3j844CMUoOb
    ekBivHv4ejUIVGbmMT5mwsCBbeg5VwFWN1Q74KHJgpTW/uY9ItbZp1chXpzJffxz
    QuU6eefkHbaHDuFYlJ9OSs6raZihyZSso/Td8M2g5O12ZbtK7Qc5AYoURfedVbRp
    K4f+LUyHH8jmtXqU1xN/4yCOUlsiS8eQ74zwPEcTXG1aRwa/QIGSJ4bvvkbka3F7
    smgpqwECgYEA7DjXusxmai1Eu3RGTfKWfLA/Br3j9FMGruxqa9R8xn6PQWDLuczl
    4ttIN9ST/lWR/XTMtdEFv0zEtze3ytVvKgbaRtqwUZCChe8wluMQRbN+/yBIW46X
    n6pdSzIfwS8Q3YgdOVZd+N1zgE7u3bUseS0uNIAHHwFNSEJA4bxhgDcCgYEAzRIt
    YdihERIZ01qN77MTxbuyXm6wuLOLaXrnomFmtjbM3iVBkrmLGhANTOUhfgPI54ka
    bXaklSqyv0zukgMn6MthXg+tSydi683jrgLg0wdhDje4Wb+1Pu6mViTYEzEHDvYj
    s8duj8J/3SEASRnnBdwku3yc+EW1zkxvcWCY7cUCgYEArmyqnvwfA3e5sNECuLvP
    8vIRF+FPWTGVVcSsMEMOf2MkVJos1F0/wms4wEDvpnV4/zYnknltTPxapQ83X0aK
    dvXoZzlDyHZ0aoFb146CjXUk6S3lP/Xib7tUeBni6LrgMTQ4oAXuDb03dB7UslD9
    Ldz2qT2ABJzpe9mwHv8C37ECgYBfvNC7EWuAkLbF2UzSTwQ4F/yZ4YtXb1ryj5J8
    WISfJM5YF4SZf03ViRDsiTwtnI66qWNRH0aO7TQt4zitqhODtw9p3l/E6kpgU+qr
    XmSfoJ5LCPBj1gBDtR6qsOC/dPAaqAba84xGSUNwdOuxNQqJzdDIRtDxh3ntKfoN
    ME+1EQKBgFQQA3KJiwu0Vy0xmvCa9L5x+Ye8XZc8rH8k/aUZqaw02kzGj+tJha5u
    y5S2rrlPsZse3QHXRO2bklSM4w8TX3OfZ+/UwnikTZXCVI0LzZfKvbQeJHe9xfcm
    HHZOuo4XBKSFKckk5uKh6uOIVkdu47wDuJ6AQLjdNY73+82T/ZBl
    -----END RSA PRIVATE KEY-----
    """ |> JOSE.JWK.from_pem(),
  ] |> JWK.new()
  @rs256_jwk_2 [
    kid: "rs256_second",
    alg: "RS256",
    key: ~S"""
    -----BEGIN RSA PRIVATE KEY-----
    MIIEogIBAAKCAQEAnNslJqT2wulBJmrgLMHW3JZv7QdiEfLItEpJqoGtQUUtqsrl
    c+pJQu0fmEjSRNFXEOXkvz3jJAKRcxBU4Q7QMMrvfLnTCpR/wIL78oKcji9RzlIg
    TIDbuKn+wBIbjZuuQ+Lf9xETFer9jhfJLdXYPwiU6umjTho4mEaTe6s36k7ete1M
    X2wMJX+AuV89g1WangZtjUxglnb+Qtfa+3z0ucnZ2cwH4OfgF4AwpcblNbqyfGg2
    S+ixxOkBchTUrOD4Pfd1kHijEjN+O65+Et4ILlsMN99CaohI6/OeEy6WCDuvG3dM
    kxb5/oHfvjtYV/P/ClxivukXDyppE8xdfsDydQIDAQABAoIBABvgOl7+zDfhekmY
    jtSFcmjrd2K5gC1OZ2rbFPJvb1n9MFt9CYArL+/r8kR/FJdUWNPQ93EhT3+z0SOQ
    0HTazBcPybXx1Fa6A2Y0IRB9M9N1B2XSZJkUAXh1Bagez7S/6R15cXIYH7sycvNQ
    uNkjevXg0Y5aDUKxGEO/rzA4QoyqRlvm81tCVRh11v0joeGQsTD9/UHg/V1QtxHP
    iKfcCdxJxTGNWClov18xkBdnWv5mMe/OZY4SswhD3tyVCNjcNBsTckotwz4EME9P
    LJNX1joitxjisfRAVQeb9FeOezIzXigzn5wRrxFOlZfU9Ox9We7n4BhXksj93O3C
    yRuVHlUCgYEAzdlGykptmXrwbK0Z0PLAJikkxHtmupE0qBVnmmh6isXf2UvhNWnb
    u8/LxjybbEepkhjaZmPoAKBOgxljiDYitOTu81WEoCpz1QBi+DHoZ01CeLUvX74B
    ZsMrN3M2CTx72elZkSB7gLntQHCcEhrLzBV7EB3n7qOYQVpcSVoEB5sCgYEAwxI1
    anLxYlFYB98cXXty0eZs/E+Ll2tPYl1iqI10iisMPHyKlBHJuSa8f32DbV+4ikQd
    h+PG54tGFoDfxtmsdckYvmtlTvuLCLOO9bkfcZRBaOZ1W0HDoTXAVdfNwrKXiSed
    VGmiEI5JbmOGKB3aAdkJLB2HKqZUuRuVme1X9y8CgYAAnZm8mSRixR9a89mT6mXw
    t0bI36WbATwrFIVOzOkw6Q6WU8fEpSBnG2P8n8nHNR+otDJTBBF5jwEtGzJVAfRw
    ng6o46SV5gqapHmnTF7pkC2WttQBcUwHxqWmcM3EkU29hRkjeflklSnEe5G77CCX
    56iKj8xVxl96Mo78GSzR6QKBgE5y4DBzEUgs1m4z98BQiRiIxoOhqc23RjGUxLxs
    RtXaAg3BOCncDXf8cAoFe/lcaWaRhh7EJ5WumP0rztK1b3ne6aiKoC9nUb6qF3AS
    huaybKu3IrMUe4w1hagAJauLDw4FdGwiHx7xWe6e77DqcGYV1m57YYRxZ9kZksxY
    euvZAoGAK5RTCTDeqwS9yToLAjzGQmKtw7n4tUJfXG3gTb7IfWRuXBW8OXnCddwu
    PUNoLKNpYkQtZJ2a4r7ZSRtlpTApiYGjIC59MjKMXuJhOqvbTsEiiOfPfEXH6kZt
    QuvGMw7oVOX6vAW3ZkC5z7DuIzpdjq5lyrtCjP5SaCbz6JDimJs=
    -----END RSA PRIVATE KEY-----
    """ |> JOSE.JWK.from_pem(),
  ] |> JWK.new()
  @rs256_jwk_3 [
    kid: @rs256_jwk_1.kid,
    alg: @rs256_jwk_1.alg,
    key: @rs256_jwk_2.key,
  ] |> JWK.new()

  describe "sign and verify" do
    test ":invalid_key" do
      payload = %{"foo" => "var"}
      not_key = "This is not KittenBlue::JWK"
      assert {:error, :invalid_key} == JWS.sign(payload, not_key)
    end

    test "HS256" do
      payload = %{"foo" => "var"}
      assert {:ok, jws} = JWS.sign(payload, @hs256_jwk_1)
      assert {:ok, payload} == JWS.verify(jws, [@hs256_jwk_1, @hs256_jwk_2])
    end

    test "RS256" do
      payload = %{"foo" => "var"}
      assert {:ok, jws} = JWS.sign(payload, @rs256_jwk_1)
      assert {:ok, payload} == JWS.verify(jws, [@rs256_jwk_1, @rs256_jwk_2])
    end
  end

  describe "verify error" do
    test ":invalid_jwt_format" do
      assert {:error, :invalid_jwt_format} == JWS.verify("invalid", [])
    end

    test ":invalid_jwt_kid" do
      payload = %{"foo" => "var"}
      assert {:ok, jws} = JWS.sign(payload, @hs256_jwk_1)
      assert {:error, :invalid_jwt_kid} == JWS.verify(jws, [@hs256_jwk_2])
      assert {:ok, jws} = JWS.sign(payload, @rs256_jwk_1)
      assert {:error, :invalid_jwt_kid} == JWS.verify(jws, [@rs256_jwk_2])
    end

    test ":invalid_jwt_signature" do
      payload = %{"foo" => "var"}
      assert {:ok, jws} = JWS.sign(payload, @hs256_jwk_1)
      assert {:error, :invalid_jwt_signature} == JWS.verify(jws, [@hs256_jwk_3])
      assert {:ok, jws} = JWS.sign(payload, @rs256_jwk_1)
      assert {:error, :invalid_jwt_signature} == JWS.verify(jws, [@rs256_jwk_3])
    end
  end
end
