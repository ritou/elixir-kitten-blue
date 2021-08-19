defmodule KittenBlue.Mixfile do
  use Mix.Project

  def project do
    [
      app: :kitten_blue,
      version: "0.4.0",
      elixir: "~> 1.3",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      description:
        "KittenBlue is a JOSE wrapper library that makes JWT implementation simpler for Elixir.",
      package: [
        maintainers: ["Ryo Ito"],
        licenses: ["MIT"],
        links: %{"GitHub" => "https://github.com/ritou/elixir-kitten-blue"}
      ],
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  def elixirc_paths(:test), do: ["lib", "test/support"]
  def elixirc_paths(_), do: ["lib"]

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:jose, "~> 1.11"},
      {:jason, "~> 1.2", optional: true},

      # HTTP Client
      {:scratcher, "~> 0.1"},

      # for test
      {:mox, "~> 1.0", only: :test},

      # for docs
      {:ex_doc, "~> 0.25.1", only: :dev, runtime: false}
    ]
  end
end
