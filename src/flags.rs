//! Flag sprites avoid platform/font-dependent rendering of regional indicators.
use egui::{ColorImage, Pos2, Rect, Response, TextureHandle, TextureOptions, Ui, Vec2};

const CODES: &[u8] = include_bytes!("../assets/flags/codes.txt");
const PNG: &[u8] = include_bytes!("../assets/flags/atlas.png");
const COLUMNS: usize = 16;
const CELL: usize = 48;
const PADDING: usize = 4;
const FLAG: usize = 40;

pub struct Flags {
    texture: Option<TextureHandle>,
    high_resolution: bool,
}
impl Flags {
    pub fn new() -> Self {
        Self {
            texture: None,
            high_resolution: false,
        }
    }
    fn load_texture(context: &egui::Context) -> Option<TextureHandle> {
        image::load_from_memory(PNG).ok().map(|image| {
            let image = if context.pixels_per_point() <= 1.25 {
                // A 26.7 px sprite covers the 22 pt widget at ordinary DPI.
                // Keep the original sprites on high-DPI displays.
                let scaled = image.resize_exact(
                    image.width() * 2 / 3,
                    image.height() * 2 / 3,
                    image::imageops::FilterType::Triangle,
                );
                drop(image);
                scaled
            } else {
                image
            };
            let rgba = image.into_rgba8();
            let image = ColorImage::from_rgba_unmultiplied(
                [rgba.width() as usize, rgba.height() as usize],
                rgba.as_raw(),
            );
            drop(rgba);
            context.load_texture("country-flags", image, TextureOptions::LINEAR)
        })
    }
    pub fn label(&mut self, ui: &mut Ui, name: &str) -> Response {
        let parts = parts(name);
        let high_resolution = ui.ctx().pixels_per_point() > 1.25;
        if (self.texture.is_none() || self.high_resolution != high_resolution)
            && parts.iter().any(|part| matches!(part, Part::Flag(_)))
        {
            self.texture = Self::load_texture(ui.ctx());
            self.high_resolution = high_resolution;
        }
        let Some(texture) = &self.texture else {
            return ui.label(crate::i18n::display(name));
        };
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            for part in parts {
                match part {
                    Part::Text(text) => {
                        ui.label(crate::i18n::display(text));
                    }
                    Part::Flag(index) => {
                        // Normalized coordinates stay identical after scaling.
                        let width = COLUMNS * CELL;
                        let height = (CODES.len() / 2).div_ceil(COLUMNS) * CELL;
                        let x = index % COLUMNS * CELL + PADDING;
                        let y = index / COLUMNS * CELL + PADDING;
                        let uv = Rect::from_min_max(
                            Pos2::new(x as f32 / width as f32, y as f32 / height as f32),
                            Pos2::new(
                                (x + FLAG) as f32 / width as f32,
                                (y + FLAG) as f32 / height as f32,
                            ),
                        );
                        ui.add(egui::Image::new((texture.id(), Vec2::splat(22.0))).uv(uv));
                    }
                }
            }
        })
        .response
    }
}
#[derive(Debug, PartialEq)]
enum Part<'a> {
    Text(&'a str),
    Flag(usize),
}
fn index(code: [u8; 2]) -> Option<usize> {
    let mut low = 0;
    let mut high = CODES.len() / 2;
    while low < high {
        let mid = (low + high) / 2;
        match CODES[mid * 2..mid * 2 + 2].cmp(&code) {
            std::cmp::Ordering::Less => low = mid + 1,
            std::cmp::Ordering::Greater => high = mid,
            std::cmp::Ordering::Equal => return Some(mid),
        }
    }
    None
}
fn regional(c: char) -> Option<u8> {
    ('\u{1f1e6}'..='\u{1f1ff}')
        .contains(&c)
        .then(|| (c as u32 - 0x1f1e6) as u8 + b'A')
}
fn parts(name: &str) -> Vec<Part<'_>> {
    let mut parts = Vec::new();
    let mut begin = 0;
    let mut chars = name.char_indices().peekable();
    while let Some((at, first)) = chars.next() {
        let Some(first) = regional(first) else {
            continue;
        };
        let Some(&(next, second_char)) = chars.peek() else {
            continue;
        };
        let Some(second) = regional(second_char) else {
            continue;
        };
        let Some(flag) = index([first, second]) else {
            continue;
        };
        if at > begin {
            parts.push(Part::Text(&name[begin..at]));
        }
        parts.push(Part::Flag(flag));
        chars.next();
        begin = next + second_char.len_utf8();
        if chars.peek().is_some_and(|(_, c)| *c == '\u{fe0f}') {
            let (at, c) = chars.next().unwrap();
            begin = at + c.len_utf8();
        }
    }
    if begin < name.len() {
        parts.push(Part::Text(&name[begin..]));
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn atlas_is_lazy_reused_and_replaced_without_leaking_on_dpi_changes() {
        let context = egui::Context::default();
        let mut flags = Flags::new();
        let _ = context.run_ui(egui::RawInput::default(), |ui| {
            flags.label(ui, "Example");
        });
        assert!(flags.texture.is_none());
        let _ = context.run_ui(egui::RawInput::default(), |ui| {
            flags.label(ui, "🇪🇪 Estonia");
        });
        let texture = flags.texture.as_ref().unwrap();
        assert_eq!(texture.size(), [512, 544]);
        let id = texture.id();
        let count = context.tex_manager().read().num_allocated();
        let _ = context.run_ui(egui::RawInput::default(), |ui| {
            flags.label(ui, "🇨🇳 China");
        });
        assert_eq!(flags.texture.as_ref().unwrap().id(), id);
        context.set_pixels_per_point(2.0);
        let _ = context.run_ui(egui::RawInput::default(), |ui| {
            flags.label(ui, "🇮🇷 Iran");
        });
        assert_eq!(flags.texture.as_ref().unwrap().size(), [768, 816]);
        assert_ne!(flags.texture.as_ref().unwrap().id(), id);
        assert_eq!(context.tex_manager().read().num_allocated(), count);
    }

    #[test]
    fn flag_pairs_are_images_and_profile_text_is_preserved() {
        assert_eq!(
            parts("🇪🇪 Эстония #7"),
            vec![
                Part::Flag(index(*b"EE").unwrap()),
                Part::Text(" Эстония #7")
            ]
        );
        assert_eq!(
            parts("a 🇺🇸🇮🇷 b"),
            vec![
                Part::Text("a "),
                Part::Flag(index(*b"US").unwrap()),
                Part::Flag(index(*b"IR").unwrap()),
                Part::Text(" b")
            ]
        );
        assert_eq!(
            parts("🍎 Example node #1"),
            vec![Part::Text("🍎 Example node #1")]
        );
        assert_eq!(parts("🇦🇦 unknown"), vec![Part::Text("🇦🇦 unknown")]);
        let image = image::load_from_memory(PNG).unwrap();
        assert_eq!(image.width() as usize, COLUMNS * CELL);
        assert!(image.height() as usize >= CODES.len() / 2 / COLUMNS * CELL);
        assert_eq!(CODES.len() / 2, 259);
    }
}
