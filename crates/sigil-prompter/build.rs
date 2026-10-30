//! Relay the rpaths published by the `iris` crate (`links = "iris_rs"`) so
//! the `sigil-prompter` binary finds libiris/liblens/libflux in the optics meson
//! build tree at runtime without `LD_LIBRARY_PATH`.

fn main() {
    let rpaths = std::env::var("DEP_IRIS_RS_RPATHS").unwrap_or_default();
    let dirs: Vec<&str> = rpaths.split(';').filter(|s| !s.is_empty()).collect();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if !dirs.is_empty() && target_os != "windows" {
        if target_os != "macos" {
            println!("cargo:rustc-link-arg=-Wl,--disable-new-dtags");
        }
        for dir in &dirs {
            println!("cargo:rustc-link-arg=-Wl,-rpath,{dir}");
        }
    }
}
