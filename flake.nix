{
  description = "Zann dev shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          k6
          pkg-config
          openssl
          jemalloc
          llvm
          libxkbcommon
          wayland
          wayland-protocols
          glib
          gtk3
          gdk-pixbuf
          pango
          cairo
          atk
          libsoup_3
          webkitgtk_4_1
          xorg.xvfb
          libayatana-appindicator
        ];
        LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [
          pkgs.openssl
          pkgs.libxkbcommon
          pkgs.wayland
          pkgs.glib
          pkgs.gtk3
          pkgs.gdk-pixbuf
          pkgs.pango
          pkgs.cairo
          pkgs.atk
          pkgs.libsoup_3
          pkgs.webkitgtk_4_1
          pkgs.libayatana-appindicator
        ];
        OPENSSL_DIR = pkgs.openssl.dev;
        OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
        OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";
      };
    };
}
