fn main() {
    println!("cargo:rerun-if-changed=target.json");
    println!("cargo:rerun-if-changed=layout.ld");

    let efidisk_path_env_name = "EFIDISK_PATH";
    println!("cargo:rerun-if-env-changed={}", efidisk_path_env_name);
    let efidisk_path_str = match std::env::var(efidisk_path_env_name) {
        Ok(path) => path,
        Err(_error) => {
            eprintln!("{} must be set", efidisk_path_env_name);
            std::process::exit(1);
        }
    };
    println!("cargo:rerun-if-changed={}", efidisk_path_str);

    let efidisk_path_non_canonicalized = std::path::Path::new(efidisk_path_str.as_str());
    if !efidisk_path_non_canonicalized.exists() {
        eprintln!("{} must exist", efidisk_path_str);
        std::process::exit(1);
    }
    let efidisk_path = efidisk_path_non_canonicalized.canonicalize().unwrap();

    let filename = efidisk_path.file_name().unwrap();
    if filename.to_str().unwrap() != "libefidisk.a" {
        eprintln!("{}={:?} must be a path to libefidisk.a", efidisk_path_env_name, efidisk_path);
        std::process::exit(1)
    }
    println!("cargo:rustc-link-search=native={}", efidisk_path.parent().unwrap().display());
    println!("cargo:rustc-link-lib=static=efidisk", );
}
