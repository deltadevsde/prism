use sp1_build::{BuildArgs, build_program_with_args, vkeys};
use std::{fs, path::PathBuf};

fn main() {
    let skip_program_build = std::env::var("SP1_SKIP_PROGRAM_BUILD")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    // Skips the sp1 build if the SP1_SKIP_PROGRAM_BUILD=true
    if skip_program_build {
        println!("cargo::warning=Skipping SP1 build.");
        return;
    }

    // Build the base prover
    let base_prover_args = BuildArgs {
        output_directory: Some("../../../elf/".to_string()),
        binaries: vec!["base_prover".to_string()],
        elf_name: Some("base-riscv32im-succinct-zkvm-elf".to_string()),
        ..Default::default()
    };
    build_program_with_args("../sp1", base_prover_args.clone());

    // Build the recursive prover
    let recursive_prover_args = BuildArgs {
        output_directory: Some("../../../elf/".to_string()),
        binaries: vec!["recursive_prover".to_string()],
        elf_name: Some("recursive-riscv32im-succinct-zkvm-elf".to_string()),
        ..Default::default()
    };
    build_program_with_args("../sp1", recursive_prover_args.clone());

    let base_vkey = vkeys("../sp1", base_prover_args)
        .get("base_prover")
        .expect("Failed to get base vkey")
        .clone();

    let recursive_vkey = vkeys("../sp1", recursive_prover_args)
        .get("recursive_prover")
        .expect("Failed to get recursive vkey")
        .clone();

    let keys_dir = PathBuf::from("../../../verification_keys");
    fs::create_dir_all(&keys_dir).expect("Failed to create verification_keys directory");

    let keys_path = keys_dir.join("keys.json");
    let keys_content = format!(
        r#"{{"base_vk": "{}", "recursive_vk": "{}"}}"#,
        base_vkey, recursive_vkey
    );
    fs::write(&keys_path, keys_content).expect("Failed to write keys.json");
}
