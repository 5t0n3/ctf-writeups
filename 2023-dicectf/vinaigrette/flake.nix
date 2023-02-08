{
  outputs = {
    self,
    nixpkgs,
  }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs {inherit system;};
    inherit (pkgs) mkShell python310 stdenv;
    chall-python = python310.withPackages (nixpkgs.lib.attrVals ["pwntools" "numpy" "galois"]);

    libpqov = stdenv.mkDerivation {
      pname = "libpqov";
      version = "paper";
      src = ./provided/pqov-paper.tar.gz;
      sourceRoot = ".";
      patches = [./provided/patch.diff ./t1-sk-expand.diff];

      buildInputs = [pkgs.clang];
      nativeBuildInputs = [pkgs.openssl];

      buildPhase = ''
        make libpqov.so VARIANT=2
      '';
      installPhase = ''
        install -D -m 555 libpqov.so $out/libpqov.so
      '';
    };
  in {
    devShells.${system}.default = mkShell {
      packages = [
        chall-python
      ];

      # link the libpqov library to the current directory for easy access
      shellHook = ''
        ln -sf ${libpqov}/libpqov.so libpqov.so
      '';
    };

    formatter.${system} = pkgs.alejandra;
  };
}
