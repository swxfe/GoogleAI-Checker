fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("assets/icon.ico")
            .set("ProductName", "Google AI Checker")
            .set("FileDescription", "Google AI Studio config checker")
            .compile()
            .expect("compile Windows application icon");
    }
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
