use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    #[default]
    #[serde(rename = "en")]
    English,
    #[serde(rename = "ru")]
    Russian,
    #[serde(rename = "zh-CN")]
    Chinese,
    #[serde(rename = "fa")]
    Persian,
}
impl Language {
    pub const ALL: [Self; 4] = [Self::English, Self::Russian, Self::Chinese, Self::Persian];
    pub fn code(self) -> &'static str {
        match self {
            Self::English => "en",
            Self::Russian => "ru",
            Self::Chinese => "zh-CN",
            Self::Persian => "fa",
        }
    }
    pub fn name(self) -> String {
        display(match self {
            Self::English => "English",
            Self::Russian => "Русский",
            Self::Chinese => "中文",
            Self::Persian => "فارسی",
        })
    }
    pub fn load(data: &Path) -> Self {
        std::fs::read(data.join("language.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }
    pub fn save(self, data: &Path) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new_in(data)?;
        file.write_all(&serde_json::to_vec(&self)?)?;
        file.as_file().sync_all()?;
        file.persist(data.join("language.json"))
            .map_err(|e| e.error)?;
        Ok(())
    }
}

pub fn tr(key: &str) -> String {
    display(&rust_i18n::t!(key))
}

pub fn display(text: &str) -> String {
    if !text.chars().any(|c| ('\u{0600}'..='\u{08ff}').contains(&c)) {
        return text.to_owned();
    }
    let shaped = arabic_reshaper::arabic_reshape(text);
    let bidi = unicode_bidi::BidiInfo::new(&shaped, None);
    bidi.paragraphs
        .iter()
        .map(|p| bidi.reorder_line(p, p.range.clone()).into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let system = if cfg!(windows) {
        "C:/Windows/Fonts/segoeui.ttf"
    } else if cfg!(target_os = "macos") {
        "/System/Library/Fonts/Supplemental/Arial.ttf"
    } else {
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    };
    if let Ok(bytes) = std::fs::read(system) {
        fonts
            .font_data
            .insert("system-ui".into(), egui::FontData::from_owned(bytes));
        fonts
            .families
            .get_mut(&egui::FontFamily::Proportional)
            .unwrap()
            .insert(0, "system-ui".into());
    }
    for (name, bytes) in [
        (
            "noto-arabic",
            include_bytes!("../assets/fonts/notosansarabic.ttf").as_slice(),
        ),
        (
            "noto-cjk",
            include_bytes!("../assets/fonts/notosanssc.ttf").as_slice(),
        ),
    ] {
        fonts
            .font_data
            .insert(name.into(), egui::FontData::from_static(bytes));
        for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
            fonts.families.get_mut(&family).unwrap().push(name.into());
        }
    }
    if &*rust_i18n::locale() == "fa" {
        fonts
            .families
            .get_mut(&egui::FontFamily::Proportional)
            .unwrap()
            .insert(0, "noto-arabic".into());
    }
    ctx.set_fonts(fonts);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn language_default_persistence_and_persian_display() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Language::load(dir.path()), Language::English);
        Language::Persian.save(dir.path()).unwrap();
        assert_eq!(Language::load(dir.path()), Language::Persian);
        assert_eq!(display("Google AI Studio"), "Google AI Studio");
        let shown = display("زبان فارسی");
        assert_ne!(shown, "زبان فارسی");
        assert!(
            shown
                .chars()
                .any(|c| ('\u{fb50}'..='\u{feff}').contains(&c))
        );
    }
    #[test]
    fn all_four_catalogs_are_complete_and_compiled() {
        let english: std::collections::BTreeMap<String, String> =
            serde_json::from_str(include_str!("../locales/en.json")).unwrap();
        assert!(english.iter().all(|(key, value)| key == value));
        assert!(
            english
                .keys()
                .all(|key| !key.chars().any(|c| ('\u{0400}'..='\u{04ff}').contains(&c)))
        );
        fn placeholders(text: &str) -> Vec<&str> {
            let mut values: Vec<_> = text
                .split("%{")
                .skip(1)
                .map(|part| {
                    part.split_once('}')
                        .expect("Unclosed translation placeholder")
                        .0
                })
                .collect();
            values.sort_unstable();
            values
        }
        for (code, json) in [
            ("ru", include_str!("../locales/ru.json")),
            ("zh-CN", include_str!("../locales/zh-CN.json")),
            ("fa", include_str!("../locales/fa.json")),
        ] {
            let values: std::collections::BTreeMap<String, String> =
                serde_json::from_str(json).unwrap();
            assert_eq!(
                english.keys().collect::<Vec<_>>(),
                values.keys().collect::<Vec<_>>()
            );
            assert!(values.values().all(|value| !value.trim().is_empty()));
            for (key, value) in &values {
                assert_eq!(placeholders(key), placeholders(value), "{code}: {key}");
                assert_eq!(
                    &*rust_i18n::t!(key.as_str(), locale = code),
                    value,
                    "{code}: {key}"
                );
            }
            assert_eq!(rust_i18n::t!("Database", locale = code), values["Database"]);
        }
        assert_eq!(rust_i18n::t!("Database", locale = "en"), "Database");
    }
}
