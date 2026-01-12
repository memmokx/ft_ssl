{
  pkgs ? import <nixpkgs> { },
}:
pkgs.mkShell.override { stdenv = pkgs.llvmPackages_21.stdenv; } {
  packages = [
    pkgs.clang-tools
    pkgs.bear
    pkgs.libbsd
    pkgs.criterion
  ];
  buildInputs = [
    (pkgs.writeScriptBin "bmake" ''
      #!${pkgs.stdenv.shell}
      exec ${pkgs.bear}/bin/bear -- make "$@"
    '')
  ];
}
