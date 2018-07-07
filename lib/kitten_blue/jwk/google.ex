defmodule KittenBlue.JWK.Google do
  @moduledoc """
  Handling module for Google Public JWKs
  """

  require Logger

  # see https://developers.google.com/identity/protocols/OpenIDConnect
  @google_jwks_uri "https://www.googleapis.com/oauth2/v3/certs"

  @doc """
  This function fetch Google JWK Sets and return the list of `KittenBlue.JWK`.

  ## Examples

      iex> KittenBlue.JWK.Google.fetch!()
      [     
        %KittenBlue.JWK{
          alg: "RS256",
          key: %JOSE.JWK{
            fields: %{
              "alg" => "RS256",
              "kid" => "4ef5118b0800bd60a4194186dcb538fc66e5eb34",
              "use" => "sig"
            },
            keys: :undefined,
            kty: {:jose_jwk_kty_rsa,
              {:RSAPublicKey,
              28476875648721430364188748069991806407446391450373045237923762311151009162921226253790824442505385585760732916607116438838248229723204601135715042657593479636219565745251068995383455309324246029645697720081638829054979172310837551569227970489185383795840331251273817798301830005422761396312919579380879507526326553332110468129972850911213822427291482233788412930127022336316623384602807587333085533862008937303422811962712539911685812228824633770949283643459223554618469656343403152537435626750336345544118558104593194249902094334930123144035611712340631611229262692299252575582560206205278645742069502946607521835099,
              65537}}
          },
          kid: "4ef5118b0800bd60a4194186dcb538fc66e5eb34"
        },
        %KittenBlue.JWK{
          alg: "RS256",
          key: %JOSE.JWK{
            fields: %{
              "alg" => "RS256",
              "kid" => "4129db2ea1860d2e871ee48506287fb05b04ca3f",
              "use" => "sig"
            },
            keys: :undefined,
            kty: {:jose_jwk_kty_rsa,
              {:RSAPublicKey,
              22609561106030035864482994811877141824726126803777462187648248944200098073331236741294232586553300034895012108018434924729133961311183119141914600651954926309301332274897870471122898299742307430511282554878657777308136016225973120369034252221550856774547365225662288681658668758322854479413570330389061522515472701665508175326183008659994223993772082779679322909193619920243402323372013460399491079488825891466897860506499022502474569809346311328649517115778556011555295770068761196334945203754564406086391916223828979710434236708178064890005597548004735093378516718512005576664304324911503655030914082941717001104327,
              65537}}
          },
          kid: "4129db2ea1860d2e871ee48506287fb05b04ca3f"
        }
      ]

  """
  @spec fetch!() :: [KittenBlue.JWK.t()] | nil
  def fetch!() do
    case HTTPoison.get(@google_jwks_uri) do
      {:ok, %HTTPoison.Response{status_code: 200, body: body}} ->
        Poison.decode!(body) |> KittenBlue.JWK.public_jwk_sets_to_list()

      {:ok, %HTTPoison.Response{} = res} ->
        Logger.warn("HTTPoison.get returned {:ok, #{inspect(res)}}")
        nil

      {:error, %HTTPoison.Error{} = error} ->
        Logger.warn("HTTPoison.get returned {:error, #{inspect(error)}}")
        nil
    end
  end
end
