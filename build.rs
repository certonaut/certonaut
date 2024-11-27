use std::fs;

fn main() {
    let cargo_lock = fs::read_to_string("Cargo.lock").expect("Failed to read Cargo.lock");
    let lockfile: toml::Value = toml::from_str(&cargo_lock).expect("Failed to parse Cargo.lock");

    // Extract the `reqwest` version
    let reqwest_version = lockfile["package"]
        .as_array()
        .expect("Expected package array")
        .iter()
        .find(|pkg| pkg["name"].as_str() == Some("reqwest"))
        .and_then(|pkg| pkg["version"].as_str())
        .expect("Failed to find reqwest version");
    println!("cargo:rustc-env=REQWEST_VERSION={}", reqwest_version);
    println!("cargo::rerun-if-changed=testdata");
}
