use std::fs;

fn main() {
    // reqwest version extraction
    let cargo_lock = fs::read_to_string("Cargo.lock").expect("Failed to read Cargo.lock");
    let lockfile: toml::Value = toml::from_str(&cargo_lock).expect("Failed to parse Cargo.lock");
    let reqwest_version = lockfile["package"]
        .as_array()
        .expect("Expected package array")
        .iter()
        .find(|pkg| pkg["name"].as_str() == Some("reqwest"))
        .and_then(|pkg| pkg["version"].as_str())
        .expect("Failed to find reqwest version");
    println!("cargo:rustc-env=REQWEST_VERSION={reqwest_version}");
    println!("cargo::rerun-if-changed=testdata");

    #[cfg(all(target_os = "linux", feature = "magic-solver"))]
    build_bpf_skeleton();
}

#[allow(dead_code)]
const SRC: &str = "src/bpf/port_mapper.bpf.c";

#[cfg(all(target_os = "linux", feature = "magic-solver"))]
fn build_bpf_skeleton() {
    let out = std::path::PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("port_mapper.skel.rs");

    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    libbpf_cargo::SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            std::ffi::OsStr::new("-I"),
            vmlinux::include_path_root().join(arch).as_os_str(),
        ])
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
}
