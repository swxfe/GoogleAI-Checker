use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedBrowser {
    pub name: String,
    pub path: PathBuf,
    pub is_default_candidate: bool,
}

pub struct BrowserDetector;

impl BrowserDetector {
    /// Detects all supported Chromium-based browsers available on the system
    pub fn detect_all() -> Vec<DetectedBrowser> {
        let mut list = Vec::new();

        #[cfg(target_os = "windows")]
        {
            Self::detect_windows(&mut list);
        }

        #[cfg(target_os = "macos")]
        {
            Self::detect_macos(&mut list);
        }

        #[cfg(target_os = "linux")]
        {
            Self::detect_linux(&mut list);
        }

        // Generic fallback check in PATH
        Self::detect_from_path(&mut list);

        // Deduplicate by canonicalized/normalized path
        let mut unique: Vec<DetectedBrowser> = Vec::new();
        for mut b in list {
            b.path = dunce::canonicalize(&b.path).unwrap_or(b.path);
            b.name = Self::product_name(&b.path).unwrap_or(b.name);
            if !unique.iter().any(|u| Self::same_path(&u.path, &b.path)) {
                unique.push(b);
            }
        }

        unique
    }
    pub fn same_path(a: &std::path::Path, b: &std::path::Path) -> bool {
        let a = dunce::canonicalize(a).unwrap_or_else(|_| a.to_owned());
        let b = dunce::canonicalize(b).unwrap_or_else(|_| b.to_owned());
        #[cfg(windows)]
        {
            a.to_string_lossy()
                .eq_ignore_ascii_case(&b.to_string_lossy())
        }
        #[cfg(not(windows))]
        {
            a == b
        }
    }
    pub fn product_name(path: &std::path::Path) -> Option<String> {
        #[cfg(windows)]
        unsafe {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{
                GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
            };
            let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let size = GetFileVersionInfoSizeW(wide.as_ptr(), std::ptr::null_mut());
            if size == 0 || size > 4 * 1024 * 1024 {
                return None;
            }
            let mut info = vec![0u8; size as usize];
            if GetFileVersionInfoW(wide.as_ptr(), 0, size, info.as_mut_ptr().cast()) == 0 {
                return None;
            }
            let translation: Vec<u16> = "\\VarFileInfo\\Translation"
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let mut pointer = std::ptr::null_mut();
            let mut length = 0;
            if VerQueryValueW(
                info.as_ptr().cast(),
                translation.as_ptr(),
                &mut pointer,
                &mut length,
            ) == 0
                || pointer.is_null()
                || length < 4
            {
                return None;
            }
            let languages = std::slice::from_raw_parts(pointer.cast::<u16>(), length as usize / 2);
            for language in languages.as_chunks::<2>().0 {
                let key: Vec<u16> = format!(
                    "\\StringFileInfo\\{:04x}{:04x}\\ProductName",
                    language[0], language[1]
                )
                .encode_utf16()
                .chain(Some(0))
                .collect();
                if VerQueryValueW(
                    info.as_ptr().cast(),
                    key.as_ptr(),
                    &mut pointer,
                    &mut length,
                ) != 0
                    && !pointer.is_null()
                    && length > 0
                {
                    let name = String::from_utf16_lossy(std::slice::from_raw_parts(
                        pointer.cast::<u16>(),
                        length as usize,
                    ))
                    .trim_end_matches('\0')
                    .trim()
                    .to_owned();
                    if !name.is_empty() {
                        return Some(name);
                    }
                }
            }
            None
        }
        #[cfg(not(windows))]
        {
            path.to_string_lossy()
                .to_lowercase()
                .contains("helium")
                .then(|| "Helium".into())
        }
    }

    /// Returns the best detected browser executable
    #[cfg(test)]
    pub fn find_best() -> Option<PathBuf> {
        let all = Self::detect_all();
        // Prefer edge on windows or chrome, otherwise first available
        all.iter()
            .find(|b| b.is_default_candidate)
            .or_else(|| all.first())
            .map(|b| b.path.clone())
    }

    #[cfg(target_os = "windows")]
    fn registry_browser(
        hive: windows_sys::Win32::System::Registry::HKEY,
        key: &str,
    ) -> Option<PathBuf> {
        use windows_sys::Win32::System::Registry::{
            RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6432KEY, RRF_SUBKEY_WOW6464KEY,
            RegGetValueW,
        };
        let key: Vec<u16> = key.encode_utf16().chain(Some(0)).collect();
        for view in [RRF_SUBKEY_WOW6464KEY, RRF_SUBKEY_WOW6432KEY] {
            let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | view;
            let mut size = 0;
            // Read App Paths directly; no shell process or persistent registry handle.
            unsafe {
                if RegGetValueW(
                    hive,
                    key.as_ptr(),
                    std::ptr::null(),
                    flags,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut size,
                ) != 0
                    || size == 0
                    || size > 65536
                {
                    continue;
                }
                let mut value = vec![0u16; (size as usize).div_ceil(2)];
                if RegGetValueW(
                    hive,
                    key.as_ptr(),
                    std::ptr::null(),
                    flags,
                    std::ptr::null_mut(),
                    value.as_mut_ptr().cast(),
                    &mut size,
                ) != 0
                {
                    continue;
                }
                let length = value.iter().position(|c| *c == 0).unwrap_or(value.len());
                let path = PathBuf::from(
                    String::from_utf16_lossy(&value[..length])
                        .trim()
                        .trim_matches('"'),
                );
                if path.is_file() {
                    return Some(path);
                }
            }
        }
        None
    }

    #[cfg(target_os = "windows")]
    fn detect_windows(list: &mut Vec<DetectedBrowser>) {
        use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        for (exe, name) in [
            ("msedge.exe", "Microsoft Edge"),
            ("chrome.exe", "Google Chrome"),
            ("brave.exe", "Brave Browser"),
        ] {
            let key = format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe}");
            for hive in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
                if let Some(path) = Self::registry_browser(hive, &key) {
                    list.push(DetectedBrowser {
                        name: name.into(),
                        path,
                        is_default_candidate: exe == "msedge.exe",
                    });
                }
            }
        }
        let program_files =
            std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
        let program_files_x86 =
            std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| r"C:\Program Files (x86)".into());
        let local_appdata = std::env::var("LOCALAPPDATA").unwrap_or_default();

        let edge_candidates = [
            PathBuf::from(&program_files_x86).join(r"Microsoft\Edge\Application\msedge.exe"),
            PathBuf::from(&program_files).join(r"Microsoft\Edge\Application\msedge.exe"),
            PathBuf::from(&local_appdata).join(r"Microsoft\Edge\Application\msedge.exe"),
        ];

        for path in &edge_candidates {
            if path.exists() {
                list.push(DetectedBrowser {
                    name: "Microsoft Edge".to_string(),
                    path: path.clone(),
                    is_default_candidate: true,
                });
                break;
            }
        }

        let chrome_candidates = [
            PathBuf::from(&program_files).join(r"Google\Chrome\Application\chrome.exe"),
            PathBuf::from(&program_files_x86).join(r"Google\Chrome\Application\chrome.exe"),
            PathBuf::from(&local_appdata).join(r"Google\Chrome\Application\chrome.exe"),
        ];

        for path in &chrome_candidates {
            if path.exists() {
                list.push(DetectedBrowser {
                    name: "Google Chrome".to_string(),
                    path: path.clone(),
                    is_default_candidate: list.is_empty(),
                });
                break;
            }
        }

        let brave_candidates = [
            PathBuf::from(&program_files)
                .join(r"BraveSoftware\Brave-Browser\Application\brave.exe"),
            PathBuf::from(&local_appdata)
                .join(r"BraveSoftware\Brave-Browser\Application\brave.exe"),
        ];

        for path in &brave_candidates {
            if path.exists() {
                list.push(DetectedBrowser {
                    name: "Brave Browser".to_string(),
                    path: path.clone(),
                    is_default_candidate: false,
                });
                break;
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn detect_macos(list: &mut Vec<DetectedBrowser>) {
        let candidates = [
            (
                "Google Chrome",
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                true,
            ),
            (
                "Microsoft Edge",
                "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                true,
            ),
            (
                "Brave Browser",
                "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
                false,
            ),
            (
                "Chromium",
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
                false,
            ),
        ];

        for (name, path_str, is_def) in &candidates {
            let path = PathBuf::from(path_str);
            if path.exists() {
                list.push(DetectedBrowser {
                    name: name.to_string(),
                    path,
                    is_default_candidate: *is_def,
                });
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn detect_linux(list: &mut Vec<DetectedBrowser>) {
        let candidates = [
            ("google-chrome", "Google Chrome", true),
            ("google-chrome-stable", "Google Chrome Stable", true),
            ("chromium", "Chromium", true),
            ("chromium-browser", "Chromium Browser", true),
            ("microsoft-edge", "Microsoft Edge", false),
            ("brave-browser", "Brave Browser", false),
        ];

        for (bin, name, is_def) in &candidates {
            let common_path = PathBuf::from(format!("/usr/bin/{bin}"));
            if common_path.exists() {
                list.push(DetectedBrowser {
                    name: name.to_string(),
                    path: common_path,
                    is_default_candidate: *is_def,
                });
            }
        }
    }

    fn detect_from_path(list: &mut Vec<DetectedBrowser>) {
        let bins = if cfg!(windows) {
            vec!["msedge.exe", "chrome.exe", "brave.exe"]
        } else {
            vec![
                "google-chrome",
                "chromium",
                "chromium-browser",
                "brave-browser",
            ]
        };

        if let Some(paths) = std::env::var_os("PATH") {
            let dirs: Vec<_> = std::env::split_paths(&paths).collect();
            for bin in bins {
                if let Some(p) = dirs.iter().map(|dir| dir.join(bin)).find(|p| p.is_file()) {
                    list.push(DetectedBrowser {
                        name: bin.into(),
                        path: p,
                        is_default_candidate: list.is_empty(),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "Local browser discovery timing; no browser is launched"]
    fn browser_discovery_benchmark() {
        let mut times = Vec::new();
        for _ in 0..7 {
            let start = std::time::Instant::now();
            let browsers = BrowserDetector::detect_all();
            std::hint::black_box(browsers);
            times.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        times.sort_by(f64::total_cmp);
        println!(
            "Browser discovery milliseconds: median={:.2}, max={:.2}",
            times[3], times[6]
        );
    }

    #[test]
    fn test_detect_browsers() {
        let browsers = BrowserDetector::detect_all();
        println!("Detected browsers: {:?}", browsers);
        let best = BrowserDetector::find_best();
        println!("Best browser: {:?}", best);
    }
}
