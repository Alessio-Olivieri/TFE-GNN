{ pkgs ? import <nixpkgs> {} }:
(import ./shell.nix { inherit pkgs; }).overrideAttrs (old: {
  nativeBuildInputs = (old.nativeBuildInputs or []) ++ [ pkgs.wireshark-cli ];
})
