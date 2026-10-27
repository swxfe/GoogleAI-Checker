use anyhow::{Context, Result, bail};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Component, Path},
};
const MAX_ARCHIVE: u64 = 512 * 1024 * 1024;
pub fn extract_zip(archive: &Path, root: &Path) -> Result<()> {
    let mut zip = zip::ZipArchive::new(File::open(archive)?)?;
    if zip.len() > 30000 {
        bail!("Слишком много файлов в архиве");
    }
    let mut total = 0u64;
    let mut links = Vec::new();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry.name();
        #[cfg(windows)]
        if name
            .split('/')
            .any(|part| part.contains(':') || part.ends_with(['.', ' ']))
        {
            bail!("Небезопасное Windows имя файла ZIP");
        }
        if name.contains('\\') || name.split('/').any(|p| p == "..") {
            bail!("Небезопасный путь в ZIP");
        }
        let relative = entry
            .enclosed_name()
            .context("Путь ZIP выходит за каталог установки")?;
        if relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
        {
            bail!("Небезопасный путь ZIP");
        }
        let dest = root.join(relative);
        total = total
            .checked_add(entry.size())
            .context("Переполнение размера ZIP")?;
        if total > 2 * 1024 * 1024 * 1024 || entry.size() > MAX_ARCHIVE {
            bail!("Слишком большой распакованный архив");
        }
        let mode = entry.unix_mode().unwrap_or(0);
        if mode & 0o170000 == 0o120000 {
            if entry.size() > 4096 {
                bail!("Слишком длинная символическая ссылка ZIP");
            }
            let mut target = String::new();
            entry.read_to_string(&mut target)?;
            let target = Path::new(&target);
            if target.is_absolute()
                || target
                    .components()
                    .any(|c| matches!(c, Component::Prefix(_) | Component::RootDir))
            {
                bail!("Абсолютная ссылка ZIP");
            }
            let joined = dest
                .parent()
                .context("Некорректный путь ссылки")?
                .join(target);
            let mut normalized = std::path::PathBuf::new();
            for c in joined.components() {
                match c {
                    Component::ParentDir => {
                        normalized.pop();
                    }
                    Component::CurDir => (),
                    _ => normalized.push(c.as_os_str()),
                }
            }
            if !normalized.starts_with(root) {
                bail!("Ссылка ZIP выходит за каталог установки");
            }
            links.push((dest, target.to_owned()));
            continue;
        }
        if mode & 0o170000 != 0 && mode & 0o170000 != 0o100000 && mode & 0o170000 != 0o040000 {
            bail!("Неподдерживаемый тип файла ZIP");
        }
        if entry.is_dir() {
            fs::create_dir_all(&dest)?;
            continue;
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out = File::options().create_new(true).write(true).open(&dest)?;
        let mut buffer = [0u8; 65536];
        let mut actual = 0u64;
        loop {
            let n = entry.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            actual += n as u64;
            if actual > entry.size() {
                bail!("Файл ZIP превышает заявленный размер");
            }
            out.write_all(&buffer[..n])?;
        }
        if actual != entry.size() {
            bail!("Размер файла ZIP не совпал");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                &dest,
                fs::Permissions::from_mode(if mode & 0o111 != 0 { 0o755 } else { 0o644 }),
            )?;
        }
    }
    #[cfg(windows)]
    if !links.is_empty() {
        bail!("Windows ZIP содержит неожиданную символическую ссылку");
    }
    #[cfg(unix)]
    for (dest, target) in &links {
        {
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }
            std::os::unix::fs::symlink(target, dest)?;
        }
    }
    for (dest, _) in links {
        if !dest.canonicalize()?.starts_with(root.canonicalize()?) {
            bail!("Ссылка ZIP выходит за bin");
        }
    }
    Ok(())
}
