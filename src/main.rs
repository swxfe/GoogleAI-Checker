#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod app;
mod browser;
mod checker;
mod events;
mod flags;
mod i18n;
mod sandbox;
mod state;
#[cfg(feature = "qa-screenshot")]
mod subscription;
mod throne;
rust_i18n::i18n!("locales", fallback = "en");
const THRONE_VERSION: &str = env!("CHECKER_THRONE_VERSION");

fn main() -> eframe::Result {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--checker-core-host")) {
        // The host owns the core IPC peer and process tree, without creating a GUI.
        std::process::exit(throne::runtime::host::entry());
    }
    // Internal core hosts above must bypass the GUI instance mutex.
    let instance = match single_instance::SingleInstance::new("googleai-checker-gui") {
        Ok(instance) => instance,
        Err(error) => {
            eprintln!("Cannot acquire application instance lock: {error}");
            return Err(eframe::Error::AppCreation(Box::new(error)));
        }
    };
    if !instance.is_single() {
        return Ok(());
    }
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::WARN)
        .init();
    eframe::run_native(
        "Google AI Checker",
        native_options(),
        Box::new(|cc| Ok(Box::new(app::CheckerApp::new(cc)))),
    )
}

fn native_options() -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1160.0, 760.0])
            .with_min_inner_size([850.0, 600.0])
            .with_transparent(false),
        vsync: true,
        dithering: false,
        #[cfg(windows)]
        renderer: eframe::Renderer::Wgpu,
        #[cfg(windows)]
        wgpu_options: eframe::egui_wgpu::WgpuConfiguration {
            // Use the Windows compositor's DirectX swap chain, avoiding WGL
            // buffer swaps when this event-driven window wakes from idle.
            supported_backends: eframe::wgpu::Backends::DX12,
            present_mode: eframe::wgpu::PresentMode::Fifo,
            desired_maximum_frame_latency: Some(2),
            ..Default::default()
        },
        #[cfg(not(windows))]
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    }
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
