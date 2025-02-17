{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    git-hooks-nix.url = "github:cachix/git-hooks.nix";
    ig.url = "github:mitchellh/zig-overlay";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        inputs.git-hooks-nix.flakeModule
      ];
      systems = [
        "x86_64-linux"
      ];
      perSystem =
        { config, pkgs, ... }:
        {
          devShells.default = pkgs.mkShell {
            nativeBuildInputs = [
              pkgs.zls
              pkgs.zig
              pkgs.sqlite
              config.pre-commit.settings.enabledPackages
            ];
            shellHook = ''
              ${config.pre-commit.installationScript}
              echo 1>&2 "Welcome to the development shell!"
            '';
          };
          pre-commit = {
            settings = {
              default_stages = [
                "pre-commit"
                "pre-push"
              ];
              hooks = {
                actionlint.enable = true;
                typos = {
                  excludes = [
                    ".*\.txt"
                  ];
                  enable = true;
                  settings.configuration = ''
                    [default]
                    extend-ignore-identifiers-re = [
                        "tpub",
                        "xpub",
                        "zpub",
                        "tpub",
                        "tprv",
                    ]

                  '';
                };
                markdownlint = {
                  enable = true;
                  settings.configuration = {
                    MD001 = false;
                    MD013 = false;
                  };
                };
                zigfmt = {
                  enable = true;
                  name = "zig-fmt";
                  files = "\\.zig$";
                  entry = "${pkgs.zig}/bin/zig fmt --check";
                };

              };
            };
          };
        };
    };
}
