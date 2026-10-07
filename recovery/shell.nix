{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  packages = [ pkgs.python312 pkgs.uv ];
  LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.stdenv.cc.cc.lib pkgs.zlib ]
    + ":/run/opengl-driver/lib";
  shellHook = ''
    export UV_CACHE_DIR="$PWD/.recovery-cache/uv"
    export CUBLAS_WORKSPACE_CONFIG=:4096:8
    export PYTHONHASHSEED=32
    export OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=4
  '';
}
