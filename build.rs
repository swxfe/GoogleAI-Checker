fn main() {
    println!("cargo:rerun-if-changed=src/allocator.c");
    cc::Build::new()
        .file("src/allocator.c")
        .include(std::env::var("DEP_MIMALLOC_INCLUDE_DIR").expect("mimalloc headers"))
        .compile("checker_allocator");
    println!("cargo:rerun-if-changed=throne-version.txt");
    let version = include_str!("throne-version.txt").trim();
    assert!(
        !version.is_empty()
            && version.len() <= 80
            && version
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".-+".contains(&c)),
        "throne-version.txt must contain a single release version"
    );
    println!("cargo:rustc-env=CHECKER_THRONE_VERSION={version}");
}
