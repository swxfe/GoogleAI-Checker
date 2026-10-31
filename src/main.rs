#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod app;
mod browser;
mod checker;
mod desktop;
mod events;
mod executor;
mod flags;
mod i18n;
mod sandbox;
mod state;
mod throne;
rust_i18n::i18n!("locales", fallback = "en");
const THRONE_VERSION: &str = env!("CHECKER_THRONE_VERSION");

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

unsafe extern "C" {
    fn checker_allocator_configure();
}

fn main() -> anyhow::Result<()> {
    // Only changes allocator policy; run before creating application threads.
    unsafe {
        checker_allocator_configure();
    }
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--checker-core-host")) {
        // The host owns the core IPC peer and process tree, without creating a GUI.
        std::process::exit(throne::runtime::host::entry());
    }
    // Internal core hosts above must bypass the GUI instance mutex.
    let instance = match single_instance::SingleInstance::new("googleai-checker-gui") {
        Ok(instance) => instance,
        Err(error) => {
            eprintln!("Cannot acquire application instance lock: {error}");
            return Err(error.into());
        }
    };
    if !instance.is_single() {
        return Ok(());
    }
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::WARN)
        .init();
    desktop::run()
}

#[cfg(test)]
mod instance_tests {
    #[test]
    fn instance_guard_rejects_a_duplicate_and_releases_on_drop() {
        let name = format!("googleai-checker-fixture-{}", std::process::id());
        let first = single_instance::SingleInstance::new(&name).unwrap();
        assert!(first.is_single());
        let second = single_instance::SingleInstance::new(&name).unwrap();
        assert!(!second.is_single());
        drop(second);
        drop(first);
        let next = single_instance::SingleInstance::new(&name).unwrap();
        assert!(next.is_single());
    }
}
