# KittenBlue

![Actions Status](https://github.com/ritou/elixir-kitten-blue/actions/workflows/ci.yml/badge.svg)

`KittenBlue` is a JOSE wrapper library that makes JWT implementation simpler.

* `KittenBlue.JWK` : Structure containing `kid`, `alg`, `JOSE.JWK` and handling functions
  * `KittenBlue.JWK.Google` : JWK Handling module for Google Public JWKs
  * `KittenBlue.JWK.Apple` : JWK Handling module for Apple Public JWKs
* `KittenBlue.JWS` : `JOSE.JWS` wrappter functions using `KittenBlue.JWK`
* `KittenBlue.JWE` : (Future Work) `JOSE.JWE` wrappter functions using `KittenBlue.JWK`
* `KittenBlue.JWT` : functions to handle JWT Claims

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `kitten_blue` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:kitten_blue, "~> 0.4"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/kitten_blue](https://hexdocs.pm/kitten_blue).

