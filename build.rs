fn main() {
    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN/../lib");
    }

    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-arg=-Wl,-rpath,@loader_path/../lib");
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