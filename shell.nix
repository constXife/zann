{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  packages = with pkgs; [
    pkg-config
    openssl
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
}
