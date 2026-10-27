mod archive;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};
use zip::write::SimpleFileOptions;

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    assets: Vec<ReleaseAsset>,
}
#[derive(Deserialize)]
struct ReleaseAsset {
    name: String,
    size: u64,
    digest: Option<String>,
}
struct Asset {
    name: String,
    size: u64,
    sha256: String,
}
#[derive(Default)]
struct Options {
    target: Option<String>,
    archive: Option<PathBuf>,
    no_build: bool,
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("dist") {
        bail!("Usage: cargo xtask dist [--target TRIPLE] [--archive ZIP] [--no-build]");
    }
    let mut options = Options::default();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--target" => options.target = Some(args.next().context("Missing --target value")?),
            "--archive" => {
                options.archive = Some(args.next().context("Missing --archive value")?.into());
            }
            "--no-build" => options.no_build = true,
            _ => bail!("Unknown argument: {arg}"),
        }
    }
    dist(options)
}

fn dist(options: Options) -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let throne_version = read_version(&fs::read_to_string(root.join("throne-version.txt"))?)?;
    let host = Command::new("rustc").arg("-vV").output()?;
    ensure!(host.status.success(), "rustc -vV failed");
    let host = String::from_utf8(host.stdout)?;
    let host = host
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .context("Missing rustc host")?;
    let target = options.target.as_deref().unwrap_or(host);
    platform(target)?;
    let metadata = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1", "--locked"])
        .current_dir(root)
        .output()?;
    ensure!(
        metadata.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&metadata.stderr)
    );
    let metadata: serde_json::Value = serde_json::from_slice(&metadata.stdout)?;
    let version = metadata["packages"]
        .as_array()
        .context("Missing packages")?
        .iter()
        .find(|p| p["name"] == "googleai-checker")
        .and_then(|p| p["version"].as_str())
        .context("Missing checker version")?;
    let target_dir = PathBuf::from(
        metadata["target_directory"]
            .as_str()
            .context("Missing target_directory")?,
    );
    let output_dir = target_dir.join("dist");
    fs::create_dir_all(&output_dir)?;
    let release = release(root, &target_dir, &throne_version, target)?;
    let asset = select_asset(&release, &throne_version, target)?;
    let archive = match options.archive {
        Some(path) => {
            verify(&path, &asset).context("Supplied Throne archive failed verification")?;
            path
        }
        None => download(root, &target_dir, &throne_version, &asset)?,
    };
    if !options.no_build {
        let mut command = Command::new("cargo");
        command.current_dir(root).args([
            "build",
            "--package",
            "googleai-checker",
            "--release",
            "--locked",
        ]);
        if let Some(target) = &options.target {
            command.args(["--target", target]);
        }
        ensure!(command.status()?.success(), "Checker release build failed");
    }
    let binary_dir = match &options.target {
        Some(target) => target_dir.join(target).join("release"),
        None => target_dir.join("release"),
    };
    let exe = if target.contains("windows") {
        "googleai-checker.exe"
    } else {
        "googleai-checker"
    };
    let binary = binary_dir.join(exe);
    ensure!(
        binary.is_file(),
        "Build output missing: {}",
        binary.display()
    );
    let staging = tempfile::Builder::new()
        .prefix("bundle-")
        .tempdir_in(&target_dir)?;
    let unpacked = staging.path().join("unpacked");
    fs::create_dir(&unpacked)?;
    archive::extract_zip(&archive, &unpacked)?;
    let entries = sorted_entries(&unpacked)?;
    let payload = if entries.len() == 1
        && entries[0].is_dir()
        && entries[0].file_name().is_some_and(|n| n == "Throne")
    {
        entries[0].clone()
    } else {
        unpacked
    };
    validate_payload(&payload, target)?;
    let name = format!("googleai-checker-{version}-{target}");
    let bundle = staging.path().join(&name);
    fs::create_dir(&bundle)?;
    fs::rename(payload, bundle.join("bin"))?;
    fs::copy(binary, bundle.join(exe))?;
    for doc in [
        "README.md",
        "README.ru.md",
        "README.zh-CN.md",
        "README.fa.md",
        "FONT-LICENSES.txt",
        "throne-version.txt",
    ] {
        if doc.starts_with("README") {
            let text = fs::read_to_string(root.join(doc))?;
            fs::write(bundle.join(doc), bundle_readme(&text))?;
        } else {
            fs::copy(root.join(doc), bundle.join(doc))?;
        }
    }
    let manifest = serde_json::json!({
        "checker_version": version, "target": target,
        "throne_version": throne_version, "throne_asset": asset.name,
        "throne_sha256": asset.sha256,
        "throne_source": format!("https://github.com/throneproj/Throne/tree/{}", throne_version),
    });
    fs::write(
        bundle.join("bundle.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    let mut output = tempfile::NamedTempFile::new_in(&output_dir)?;
    {
        let mut zip = zip::ZipWriter::new(output.as_file_mut());
        zip_tree(&mut zip, &bundle, &bundle, &name)?;
        zip.finish()?;
    }
    output.as_file().sync_all()?;
    let destination = output_dir.join(format!("{name}.zip"));
    output.persist(&destination).map_err(|e| e.error)?;
    let digest = digest(&destination)?;
    fs::write(
        destination.with_extension("zip.sha256"),
        format!("{digest}  {name}.zip\n"),
    )?;
    println!("Bundle: {}", destination.display());
    println!("SHA-256: {digest}");
    Ok(())
}

fn bundle_readme(text: &str) -> String {
    let mut lines = text.lines().peekable();
    let mut output = Vec::new();
    while let Some(line) = lines.next() {
        if line.starts_with("![") && line.ends_with("(assets/demo.png)") {
            while lines.peek().is_some_and(|line| line.is_empty()) {
                lines.next();
            }
            if lines
                .peek()
                .is_some_and(|line| line.starts_with('*') && line.ends_with('*'))
            {
                lines.next();
            }
            if output.last() == Some(&"") {
                output.pop();
            }
        } else {
            output.push(line);
        }
    }
    output.join("\n") + "\n"
}

fn read_version(text: &str) -> Result<String> {
    let version = text.trim();
    ensure!(
        !version.is_empty()
            && version.len() <= 80
            && version
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".-+".contains(&c)),
        "throne-version.txt must contain a single release version"
    );
    Ok(version.to_owned())
}

fn platform(target: &str) -> Result<&'static str> {
    match target {
        "x86_64-pc-windows-msvc" => Ok("windows64"),
        "aarch64-pc-windows-msvc" => Ok("windows-arm64"),
        "x86_64-unknown-linux-gnu" => Ok("linux-amd64"),
        "aarch64-unknown-linux-gnu" => Ok("linux-arm64"),
        "x86_64-apple-darwin" => Ok("macos-amd64"),
        "aarch64-apple-darwin" => Ok("macos-arm64"),
        _ => bail!("No Throne bundle for target {target}"),
    }
}

fn select_asset(release: &Release, version: &str, target: &str) -> Result<Asset> {
    ensure!(
        !release.draft && release.tag_name == version,
        "GitHub returned a different or draft Throne release"
    );
    let name = format!(
        "Throne-{}-{}.zip",
        version.trim_start_matches('v'),
        platform(target)?
    );
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == name)
        .with_context(|| format!("Throne {version} has no archive for {target}"))?;
    ensure!(
        asset.size > 0 && asset.size <= 512 * 1024 * 1024,
        "Invalid Throne archive size"
    );
    let sha256 = asset
        .digest
        .as_deref()
        .and_then(|s| s.strip_prefix("sha256:"))
        .context("GitHub did not provide a SHA-256 for this Throne archive")?;
    ensure!(
        sha256.len() == 64 && sha256.bytes().all(|c| c.is_ascii_hexdigit()),
        "Invalid GitHub SHA-256"
    );
    Ok(Asset {
        name,
        size: asset.size,
        sha256: sha256.to_owned(),
    })
}

fn release(root: &Path, target_dir: &Path, version: &str, target: &str) -> Result<Release> {
    let cache = target_dir.join("throne-cache");
    fs::create_dir_all(&cache)?;
    let cached = cache.join(format!("{version}-release.json"));
    if let Ok(bytes) = fs::read(&cached)
        && let Ok(release) = serde_json::from_slice::<Release>(&bytes)
        && select_asset(&release, version, target).is_ok()
    {
        return Ok(release);
    }
    println!("Fetching Throne {version} release metadata…");
    let temporary = tempfile::NamedTempFile::new_in(&cache)?;
    let url = format!("https://api.github.com/repos/throneproj/Throne/releases/tags/{version}");
    fetch(root, &url, temporary.path(), 4 * 1024 * 1024)?;
    let release: Release = serde_json::from_slice(&fs::read(temporary.path())?)?;
    select_asset(&release, version, target)?;
    temporary.persist(cached).map_err(|e| e.error)?;
    Ok(release)
}

fn fetch(root: &Path, url: &str, destination: &Path, max_bytes: u64) -> Result<()> {
    let status = Command::new(if cfg!(windows) { "curl.exe" } else { "curl" })
        .current_dir(root)
        .args([
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--user-agent",
            "googleai-checker-xtask",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--retry",
            "2",
            "--connect-timeout",
            "15",
            "--max-time",
            "300",
            "--max-filesize",
            &max_bytes.to_string(),
            "--output",
        ])
        .arg(destination)
        .arg(url)
        .status()
        .context("curl is required for cargo xtask dist")?;
    ensure!(
        status.success(),
        "Download failed: {url}. Check the release version, connection or GitHub API rate limit."
    );
    ensure!(
        destination.metadata()?.len() <= max_bytes,
        "Download exceeded its size limit"
    );
    Ok(())
}

fn digest(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn verify(path: &Path, asset: &Asset) -> Result<()> {
    ensure!(
        path.metadata()?.len() == asset.size,
        "Throne archive size mismatch"
    );
    ensure!(
        digest(path)?.eq_ignore_ascii_case(&asset.sha256),
        "Throne archive SHA-256 mismatch"
    );
    Ok(())
}

fn download(root: &Path, target: &Path, version: &str, asset: &Asset) -> Result<PathBuf> {
    let cache = target.join("throne-cache");
    fs::create_dir_all(&cache)?;
    let cached = cache.join(&asset.name);
    if verify(&cached, asset).is_ok() {
        return Ok(cached);
    }
    let temporary = tempfile::NamedTempFile::new_in(&cache)?;
    let url = format!(
        "https://github.com/throneproj/Throne/releases/download/{version}/{}",
        asset.name
    );
    println!("Downloading Throne {version}…");
    fetch(root, &url, temporary.path(), asset.size)?;
    verify(temporary.path(), asset)?;
    temporary.persist(&cached).map_err(|e| e.error)?;
    Ok(cached)
}

fn validate_payload(root: &Path, target: &str) -> Result<()> {
    let binary_dir = if target.contains("apple") {
        root.join("Throne.app/Contents/MacOS")
    } else {
        root.to_owned()
    };
    for name in if target.contains("windows") {
        ["Throne.exe", "ThroneCore.exe"]
    } else {
        ["Throne", "ThroneCore"]
    } {
        ensure!(
            binary_dir.join(name).is_file(),
            "Pinned archive lacks {name}"
        );
    }
    Ok(())
}

fn sorted_entries(root: &Path) -> Result<Vec<PathBuf>> {
    let mut entries = fs::read_dir(root)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort();
    Ok(entries)
}

fn zip_tree<W: Write + std::io::Seek>(
    zip: &mut zip::ZipWriter<W>,
    root: &Path,
    dir: &Path,
    prefix: &str,
) -> Result<()> {
    for path in sorted_entries(dir)? {
        let relative = path
            .strip_prefix(root)?
            .to_str()
            .context("Non-UTF8 bundle path")?
            .replace('\\', "/");
        let name = format!("{prefix}/{relative}");
        let metadata = fs::symlink_metadata(&path)?;
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        if metadata.file_type().is_symlink() {
            ensure!(
                path.canonicalize()?.starts_with(root.canonicalize()?),
                "Bundle symlink escapes root"
            );
            let target = fs::read_link(&path)?;
            zip.add_symlink(name, target.to_str().context("Non-UTF8 symlink")?, options)?;
        } else if metadata.is_dir() {
            zip.add_directory(format!("{name}/"), options.unix_permissions(0o755))?;
            zip_tree(zip, root, &path, prefix)?;
        } else {
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode() & 0o777
            };
            #[cfg(not(unix))]
            let mode = 0o644;
            zip.start_file(name, options.unix_permissions(mode))?;
            std::io::copy(&mut File::open(&path)?, zip)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_file_is_one_line_and_rejects_paths() {
        assert_eq!(read_version("1.4.0-beta.3\n").unwrap(), "1.4.0-beta.3");
        for text in ["", "../latest", "1.4\nother", "1.4 beta"] {
            assert!(read_version(text).is_err());
        }
    }
    #[test]
    fn release_selection_requires_exact_version_platform_and_checksum() {
        let mut release: Release = serde_json::from_value(serde_json::json!({
            "tag_name":"1.4.0-beta.3", "assets":[{
                "name":"Throne-1.4.0-beta.3-windows64.zip", "size":7,
                "digest":format!("sha256:{}", "a".repeat(64))
            }]
        }))
        .unwrap();
        assert!(select_asset(&release, "1.4.0-beta.3", "x86_64-pc-windows-msvc").is_ok());
        assert!(select_asset(&release, "1.4.0", "x86_64-pc-windows-msvc").is_err());
        assert!(select_asset(&release, "1.4.0-beta.3", "aarch64-apple-darwin").is_err());
        release.assets[0].digest = None;
        assert!(select_asset(&release, "1.4.0-beta.3", "x86_64-pc-windows-msvc").is_err());
    }
    #[test]
    fn archives_need_exact_size_and_digest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture.zip");
        fs::write(&path, b"fixture").unwrap();
        let mut asset = Asset {
            name: "fixture.zip".into(),
            size: 7,
            sha256: digest(&path).unwrap(),
        };
        verify(&path, &asset).unwrap();
        fs::write(&path, b"changed").unwrap();
        assert!(verify(&path, &asset).is_err());
        asset.sha256 = digest(&path).unwrap();
        asset.size = 8;
        assert!(verify(&path, &asset).is_err());
    }
    #[test]
    fn zip_cannot_escape_staging() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unsafe.zip");
        let mut zip = zip::ZipWriter::new(File::create(&path).unwrap());
        zip.start_file("../escape.txt", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"escape").unwrap();
        zip.finish().unwrap();
        let output = dir.path().join("output");
        fs::create_dir(&output).unwrap();
        assert!(archive::extract_zip(&path, &output).is_err());
        assert!(!dir.path().join("escape.txt").exists());
    }
}
