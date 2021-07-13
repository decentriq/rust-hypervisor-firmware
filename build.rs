fn main() {
    println!("cargo:rerun-if-changed=target.json");
    println!("cargo:rerun-if-changed=layout.ld");

    let uki_path_env_name = "UKI_PATH";
    println!("cargo:rerun-if-env-changed={}", uki_path_env_name);
    let uki_path_str = match std::env::var(uki_path_env_name) {
        Ok(path) => path,
        Err(_error) => {
            eprintln!("{} must be set", uki_path_env_name);
            std::process::exit(1);
        }
    };
    println!("cargo:rerun-if-changed={}", uki_path_str);

    let uki_path_non_canonicalized = std::path::Path::new(uki_path_str.as_str());
    if !uki_path_non_canonicalized.exists() {
        eprintln!("{} must exist", uki_path_str);
        std::process::exit(1);
    }
    let uki_path = uki_path_non_canonicalized.canonicalize().unwrap();

    let filename = uki_path.file_name().unwrap();
    if filename.to_str().unwrap() != "libuki.a" {
        eprintln!("{}={:?} must be a path to libuki.a", uki_path_env_name, uki_path);
        std::process::exit(1)
    }
    println!("cargo:rustc-link-search=native={}", uki_path.parent().unwrap().display());
    println!("cargo:rustc-link-lib=static=uki", );
}
