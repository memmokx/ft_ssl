{
  pkgs ? import <nixpkgs> { },
}:
pkgs.mkShell.override { stdenv = pkgs.llvmPackages_21.stdenv; } {
  packages = [
    pkgs.clang-tools
    pkgs.bear
    pkgs.libbsd
    pkgs.criterion
    pkgs.python313Packages.psutil # To use timeouts in lit v
    pkgs.lit
    pkgs.filecheck
  ];
  buildInputs = [
    (pkgs.writeScriptBin "bmake" ''
      #!${pkgs.stdenv.shell}
      exec ${pkgs.bear}/bin/bear -- make "$@"
    '')
    (pkgs.writeScriptBin "FileCheck" ''
      #!${pkgs.stdenv.shell}
      exec ${pkgs.filecheck}/bin/filecheck "$@"
    '')
    (pkgs.writeScriptBin "not" ''
      #!${pkgs.stdenv.shell}
      "$@"
      exit $((! $?))
    '')
  ];
}
