fn main() {
    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN/../lib");
    }

    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-arg=-Wl,-rpath,@loader_path/../lib");


        // Only needed when linking against static libyubihsm.a
        // Set YUBIHSM_STATIC=1 in CI release builds
        println!("cargo:rerun-if-env-changed=YUBIHSM_STATIC");
        if std::env::var("YUBIHSM_STATIC").is_ok() {
            println!("cargo:rustc-link-lib=static=curl");
            println!("cargo:rustc-link-lib=static=usb-1.0");

            // System frameworks needed by SecureTransport-backed curl
            println!("cargo:rustc-link-lib=framework=Security");
            println!("cargo:rustc-link-lib=framework=SystemConfiguration");
            println!("cargo:rustc-link-lib=framework=CoreFoundation");

            // System frameworks needed by libusb
            println!("cargo:rustc-link-lib=framework=IOKit");

            // Tell the linker where to find the libraries at build time
            println!("cargo:rerun-if-env-changed=BREW_LIB");
            println!("cargo:rerun-if-env-changed=CURL_LIB_DIR");
            println!("cargo:rerun-if-env-changed=LIBUSB_LIB_DIR");
            if let Ok(curl_lib_dir) = std::env::var("CURL_LIB_DIR") {
                println!("cargo:rustc-link-search={}", curl_lib_dir);
            }
            if let Ok(libusb_lib_dir) = std::env::var("LIBUSB_LIB_DIR") {
                println!("cargo:rustc-link-search={}", libusb_lib_dir);
            }
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