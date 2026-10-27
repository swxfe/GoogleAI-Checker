pub mod config;
pub mod host;
mod wire;

use crate::sandbox::process::ManagedProcess;
use anyhow::{Context, Result, ensure};
use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::PathBuf,
    process::{ChildStdin, Command},
    time::Duration,
};

#[derive(Clone)]
pub struct RuntimeConfig {
    pub database: PathBuf,
    pub throne_executable: PathBuf,
    pub data_root: PathBuf,
    pub fingerprints: HashMap<i64, String>,
}

pub struct Runtime {
    // Kill the owned process tree before removing its private files.
    process: ManagedProcess,
    core_pid: u32,
    _input: ChildStdin,
    _directory: tempfile::TempDir,
    pub proxies: HashMap<i64, String>,
}
impl Runtime {
    pub async fn start(config: RuntimeConfig, plan: config::Plan) -> Result<Self> {
        let host = std::env::current_exe()?;
        #[cfg(test)]
        let host = std::env::var_os("CHECKER_TEST_HOST")
            .map(PathBuf::from)
            .unwrap_or(host);
        Self::start_with_host(config, plan, host).await
    }
    async fn start_with_host(
        config: RuntimeConfig,
        mut plan: config::Plan,
        host_executable: PathBuf,
    ) -> Result<Self> {
        let binary_dir = dunce::canonicalize(
            config
                .throne_executable
                .parent()
                .context("Missing Throne binary directory")?,
        )?;
        let core_name = if cfg!(windows) {
            "ThroneCore.exe"
        } else {
            "ThroneCore"
        };
        let core = dunce::canonicalize(binary_dir.join(core_name))?;
        let temp_root = config.data_root.join("tmp");
        fs::create_dir_all(&temp_root)?;
        let directory = tempfile::Builder::new()
            .prefix("rust-core-")
            .tempdir_in(&temp_root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        }
        let host_path = directory.path().join(if cfg!(windows) {
            "Throne.exe"
        } else {
            "Throne"
        });
        link_or_copy(&host_executable, &host_path)?;
        link_or_copy(&core, &directory.path().join(core_name))?;
        let mut command = Command::new(&host_path);
        command.arg("--checker-core-host").current_dir(&binary_dir);
        // Keep native asset lookup beside the installed core, despite private IPC ownership.
        command.env("XRAY_LOCATION_ASSET", &binary_dir);
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("THRONE_") {
                command.env_remove(key);
            }
        }
        plan.release_ports();
        let mut process = ManagedProcess::spawn_piped(command, &directory.path().join("host.log"))?;
        let mut input = process.take_stdin().context("Missing core host stdin")?;
        let mut output = process.take_stdout().context("Missing core host stdout")?;
        let ready = tokio::task::spawn_blocking(move || -> Result<(ChildStdin, u32)> {
            host::write_message(&mut input, &plan.load)?;
            let ready: host::Ready = host::read_message(&mut output)?;
            ensure!(
                ready.error.is_none(),
                "Rust core host: {}",
                ready.error.unwrap_or_default()
            );
            // The open pipe is the host's lifetime lease.
            input.flush()?;
            let pid = ready
                .core_pid
                .filter(|pid| *pid > 0)
                .context("Core host did not report its owned core PID")?;
            Ok((input, pid))
        });
        // `process` stays in this cancellable future. Dropping it unblocks either
        // stdio operation above and kills the entire host/core tree.
        let (input, core_pid) = tokio::time::timeout(Duration::from_secs(18), ready).await???;
        ensure!(
            process.exit_status()?.is_none(),
            "Core host exited during startup"
        );
        Ok(Self {
            process,
            core_pid,
            _input: input,
            _directory: directory,
            proxies: plan.proxies,
        })
    }
    pub fn ensure_running(&mut self) -> Result<()> {
        ensure!(
            self.process.exit_status()?.is_none() && core_alive(self.core_pid)?,
            "Служебное ядро завершилось; проверка остановлена"
        );
        Ok(())
    }
}
fn core_alive(pid: u32) -> Result<bool> {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::{
            Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, STILL_ACTIVE},
            System::Threading::{
                GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            },
        };
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
                return Ok(false);
            }
            return Err(error.into());
        }
        let mut code = 0;
        let ok = GetExitCodeProcess(handle, &mut code);
        let error = std::io::Error::last_os_error();
        CloseHandle(handle);
        ensure!(ok != 0, "Could not inspect owned core: {error}");
        Ok(code == STILL_ACTIVE as u32)
    }
    #[cfg(unix)]
    {
        if unsafe { libc::kill(pid as i32, 0) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Ok(false);
            }
            return Err(error.into());
        }
        #[cfg(target_os = "linux")]
        if let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat"))
            && stat
                .rsplit_once(')')
                .is_some_and(|(_, fields)| fields.trim_start().starts_with('Z'))
        {
            return Ok(false);
        }
        Ok(true)
    }
}
fn link_or_copy(source: &std::path::Path, destination: &std::path::Path) -> Result<()> {
    if fs::hard_link(source, destination).is_err() {
        fs::copy(source, destination)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::throne::models::Profile;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn fake_exit(marker: u8) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            let mut clients = tokio::task::JoinSet::new();
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                clients.spawn(async move {
                    let mut hello = [0; 2];
                    socket.read_exact(&mut hello).await.unwrap();
                    let mut methods = vec![0; hello[1] as usize];
                    socket.read_exact(&mut methods).await.unwrap();
                    socket.write_all(&[5, 0]).await.unwrap();
                    let mut header = [0; 4];
                    socket.read_exact(&mut header).await.unwrap();
                    let count = match header[3] {
                        1 => 4,
                        4 => 16,
                        3 => socket.read_u8().await.unwrap() as usize,
                        _ => panic!("Bad SOCKS target"),
                    };
                    let mut target = vec![0; count + 2];
                    socket.read_exact(&mut target).await.unwrap();
                    socket
                        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
                        .await
                        .unwrap();
                    let byte = socket.read_u8().await.unwrap();
                    socket.write_all(&[marker, byte]).await.unwrap();
                });
            }
        });
        (address, task)
    }
    async fn routed_byte(proxy: &str, byte: u8) -> Vec<u8> {
        let mut socket = tokio::net::TcpStream::connect(proxy).await.unwrap();
        socket.write_all(&[5, 1, 0]).await.unwrap();
        let mut hello = [0; 2];
        socket.read_exact(&mut hello).await.unwrap();
        assert_eq!(hello, [5, 0]);
        socket
            .write_all(&[5, 1, 0, 3, 4, b't', b'e', b's', b't', 0, 80])
            .await
            .unwrap();
        let mut response = [0; 10];
        socket.read_exact(&mut response).await.unwrap();
        assert_eq!(&response[..2], &[5, 0]);
        socket.write_all(&[byte]).await.unwrap();
        let mut bytes = vec![0; 2];
        socket.read_exact(&mut bytes).await.unwrap();
        bytes
    }
    #[tokio::test]
    #[ignore = "Explicit official-core integration: local synthetic SOCKS routes only; requires THRONE_TEST_CORE and CHECKER_TEST_HOST"]
    async fn official_core_accepts_rust_ipc_isolates_routes_and_dies_on_drop() {
        let core = PathBuf::from(std::env::var_os("THRONE_TEST_CORE").expect("THRONE_TEST_CORE"));
        let host = PathBuf::from(std::env::var_os("CHECKER_TEST_HOST").expect("CHECKER_TEST_HOST"));
        let root = tempfile::tempdir().unwrap();
        let (one, task_one) = fake_exit(41).await;
        let (two, task_two) = fake_exit(73).await;
        let profiles = [one, two].into_iter().enumerate().map(|(id, proxy)| {
            let proxy: std::net::SocketAddr = proxy.parse().unwrap();
            let full = json!({"inbounds":[{"protocol":"socks","port":2080}],"outbounds":[{"protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":proxy.port()}]}}]});
            (Profile { id:id as i64, profile_type:"custom".into(), ..Default::default() }, json!({"type":"custom","subtype":"xrayfullconfig","config":full.to_string()}))
        }).collect();
        let source = config::Source::synthetic(profiles);
        let plan = source.build(&source.profiles).unwrap();
        let started = std::time::Instant::now();
        let mut runtime = Runtime::start_with_host(
            RuntimeConfig {
                database: root.path().join("unused.db"),
                throne_executable: core.parent().unwrap().join("Throne.exe"),
                data_root: root.path().to_owned(),
                fingerprints: HashMap::new(),
            },
            plan,
            host,
        )
        .await
        .unwrap();
        let startup = started.elapsed();
        let proxies = runtime.proxies.clone();
        let requests = (0..40).map(|index| {
            let proxy = proxies[&(index % 2)].clone();
            async move { (index, routed_byte(&proxy, index as u8).await) }
        });
        let checks = futures_util::future::join_all(requests).await;
        for (index, response) in checks {
            assert_eq!(
                response,
                [if index % 2 == 0 { 41 } else { 73 }, index as u8]
            );
        }
        runtime.ensure_running().unwrap();
        let process_id = runtime.process.id();
        // A dead core must stop the controller even before its host's poll fires.
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::{
                Foundation::{CloseHandle, WAIT_OBJECT_0},
                System::Threading::{
                    OpenProcess, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, TerminateProcess,
                    WaitForSingleObject,
                },
            };
            let handle = OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, 0, runtime.core_pid);
            assert!(!handle.is_null());
            assert_ne!(TerminateProcess(handle, 1), 0);
            assert_eq!(WaitForSingleObject(handle, 1000), WAIT_OBJECT_0);
            CloseHandle(handle);
        }
        #[cfg(unix)]
        unsafe {
            assert_eq!(libc::kill(runtime.core_pid as i32, libc::SIGKILL), 0);
        }
        assert!(runtime.ensure_running().is_err());
        drop(runtime);
        for proxy in proxies.values() {
            assert!(
                tokio::net::TcpStream::connect(proxy).await.is_err(),
                "Owned core port survived Drop"
            );
        }
        assert_eq!(fs::read_dir(root.path().join("tmp")).unwrap().count(), 0);
        task_one.abort();
        task_two.abort();
        println!(
            "Local core: startup {:?}, 40 isolated concurrent routes {:?}, owned host PID {} removed",
            startup,
            started.elapsed() - startup,
            process_id
        );
    }
    #[tokio::test]
    #[ignore = "Official core with synthetic VLESS, Xray and TLS Trojan servers, all on loopback; requires THRONE_TEST_CORE and CHECKER_TEST_HOST"]
    async fn native_protocols_match_rust_generated_profiles_on_local_servers() {
        let core = PathBuf::from(std::env::var_os("THRONE_TEST_CORE").expect("THRONE_TEST_CORE"));
        let host = PathBuf::from(std::env::var_os("CHECKER_TEST_HOST").expect("CHECKER_TEST_HOST"));
        let root = tempfile::tempdir().unwrap();
        let (exit, task) = fake_exit(91).await;
        let exit: std::net::SocketAddr = exit.parse().unwrap();
        let vless_socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let vless_port = vless_socket.local_addr().unwrap().port();
        let trojan_socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let trojan_port = trojan_socket.local_addr().unwrap().port();
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let uuid = "00000000-0000-0000-0000-000000000001";
        let raw = [
            (
                "vless",
                json!({"type":"vless","server":"127.0.0.1","server_port":vless_port,"uuid":uuid,"packet_encoding":"xudp"}),
            ),
            (
                "xrayvless",
                json!({"protocol":"vless","settings":{"address":"127.0.0.1","port":vless_port,"id":uuid,"encryption":"none"},"streamSettings":{"network":"raw","security":"none"}}),
            ),
            (
                "trojan",
                json!({"type":"trojan","server":"127.0.0.1","server_port":trojan_port,"password":"local-test-password","tls":{"enabled":true,"server_name":"localhost","certificate":[certificate.cert.pem()]}}),
            ),
        ];
        let profiles = raw
            .into_iter()
            .enumerate()
            .map(|(id, (kind, value))| {
                (
                    Profile {
                        id: id as i64,
                        profile_type: kind.into(),
                        ..Default::default()
                    },
                    value,
                )
            })
            .collect();
        let source = config::Source::synthetic(profiles);
        let mut plan = source.build(&source.profiles).unwrap();
        let mut xray: serde_json::Value = serde_json::from_str(&plan.load.xray_config).unwrap();
        xray["inbounds"].as_array_mut().unwrap().extend([
            json!({"tag":"fixture-vless-server","listen":"127.0.0.1","port":vless_port,"protocol":"vless","settings":{"clients":[{"id":uuid}],"decryption":"none"}}),
            json!({"tag":"fixture-trojan-server","listen":"127.0.0.1","port":trojan_port,"protocol":"trojan","settings":{"clients":[{"password":"local-test-password"}]},"streamSettings":{"network":"raw","security":"tls","tlsSettings":{"certificates":[{"certificate":certificate.cert.pem().lines().collect::<Vec<_>>(),"key":certificate.signing_key.serialize_pem().lines().collect::<Vec<_>>()}]}}}),
        ]);
        xray["outbounds"].as_array_mut().unwrap().push(json!({"tag":"fixture-exit","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":exit.port()}]}}));
        xray["routing"]["rules"].as_array_mut().unwrap().push(json!({"type":"field","inboundTag":["fixture-vless-server","fixture-trojan-server"],"outboundTag":"fixture-exit"}));
        plan.load.xray_config = xray.to_string();
        drop(vless_socket);
        drop(trojan_socket);
        let mut runtime = Runtime::start_with_host(
            RuntimeConfig {
                database: root.path().join("unused.db"),
                throne_executable: core.parent().unwrap().join("Throne.exe"),
                data_root: root.path().to_owned(),
                fingerprints: HashMap::new(),
            },
            plan,
            host,
        )
        .await
        .unwrap();
        for id in 0..3 {
            let response = tokio::time::timeout(
                Duration::from_secs(5),
                routed_byte(&runtime.proxies[&id], id as u8),
            )
            .await
            .unwrap();
            assert_eq!(
                response,
                [91, id as u8],
                "Native protocol {id} disagreed with the Rust-generated profile"
            );
        }
        runtime.ensure_running().unwrap();
        drop(runtime);
        task.abort();
    }
}
