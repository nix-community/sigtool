{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  nativeBuildInputs = [
    pkgs.cmake
    pkgs.pkg-config
  ];

  buildInputs = [
    (pkgs.python3.withPackages (ps: [ ps.construct ]))
    pkgs.openssl
    pkgs.libplist

    # keep this line if you use bash
    pkgs.bashInteractive
  ];
}
