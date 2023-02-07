{
  outputs = {self, nixpkgs}:
    let system = "x86_64-linux";
        pkgs = import nixpkgs {inherit system;};
        inherit (pkgs) mkShell python310 binutils;
        vol-python = python310.withPackages (nixpkgs.lib.attrVals ["pycryptodome" "yara-python" "pefile"]);
    in {
      devShells.${system}.default = mkShell {
        packages = [vol-python binutils];
      };
    };
}

