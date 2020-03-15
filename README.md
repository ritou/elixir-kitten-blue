# KittenBlue

[![Build Status](https://travis-ci.org/ritou/elixir-kitten-blue.svg?branch=master)](https://travis-ci.org/ritou/elixir-kitten-blue)

`KittenBlue` is a JOSE wrapper library that makes JWT implementation simpler.

* `KittenBlue.JWK` : Structure containing `kid`, `alg`, `JOSE.JWK` and handling functions
  * `KittenBlue.JWK.Google` : JWK Handling module for Google Public JWKs
* `KittenBlue.JWS` : `JOSE.JWS` wrappter functions using `KittenBlue.JWK`
* `KittenBlue.JWE` : (Future Work) `JOSE.JWE` wrappter functions using `KittenBlue.JWK`

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `kitten_blue` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:kitten_blue, "~> 0.1.6"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/kitten_blue](https://hexdocs.pm/kitten_blue).

