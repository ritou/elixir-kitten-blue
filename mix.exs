defmodule KittenBlue.Mixfile do
  use Mix.Project

  def project do
    [
      app: :kitten_blue,
      version: "0.1.8",
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
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"},
      {:jose, "~> 1.8"},
      {:jason, "~> 1.2", optional: true},
      {:httpoison, "~> 1.4", optional: true},

      # for test
      {:mox, "~> 0.5", only: :test},

      # for docs
      {:ex_doc, "~> 0.21.3", only: :dev, runtime: false}
    ]
  end
end
