fn main() {
    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN/../lib");
    }

    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-arg=-Wl,-rpath,@loader_path/../lib");

        // libyubihsm.a (static) has unresolved symbols for curl and libusb.
        // These will be satisfied by:
        //   - libcurl: system dylib (ships with macOS)
        //   - libusb:  bundled dylib in ../lib/
        println!("cargo:rustc-link-lib=curl");
        println!("cargo:rustc-link-lib=usb-1.0");

        // Where to find libusb at build time
        println!("cargo:rerun-if-env-changed=BREW_LIB");
        if let Ok(brew_lib) = std::env::var("BREW_LIB") {
            println!("cargo:rustc-link-search={}/libusb/lib", brew_lib);
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Transitive dependencies of static yubihsm.lib
        println!("cargo:rustc-link-lib=winhttp");
        println!("cargo:rustc-link-lib=winusb");
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=setupapi");
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=crypt32");
    }
}