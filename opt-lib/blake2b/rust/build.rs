use std::env;

fn main() {
    let target = env::var("TARGET").unwrap();

    let mut builder = cc::Build::new();
    if !target.contains("zkvm") {
        builder.compiler(clang_finder::find());
    }
    builder.file("src/blake2b.c").include("src").opt_level(3);
    if target.contains("riscv64") && !target.contains("zkvm") {
        builder.flag("-march=rv64imc_zba_zbb_zbc_zbs");
    }
    builder.compile("blake2b");

    println!("cargo:rerun-if-changed=src/blake2b.c");
    println!("cargo:rerun-if-changed=src/blake2b.h");
    println!("cargo:rerun-if-changed=build.rs");
}
