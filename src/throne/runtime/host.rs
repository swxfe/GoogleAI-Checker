//! Internal GUI-free mode. The official core requires its IPC server to be its
//! parent named Throne in the same directory; this host satisfies that contract.
use super::wire::{self, LoadConfig, MAX_MESSAGE};
use crate::sandbox::process::ManagedProcess;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    io::{Read, Write},
    process::Command,
    time::Duration,
};
use tokio::time::timeout;

#[derive(Serialize, Deserialize)]
pub struct Ready {
    pub error: Option<String>,
    pub core_pid: Option<u32>,
}

pub fn read_message<T: DeserializeOwned>(input: &mut impl Read) -> Result<T> {
    let mut header = [0; 4];
    input.read_exact(&mut header)?;
    let count = u32::from_le_bytes(header) as usize;
    ensure!(count <= MAX_MESSAGE, "Host message exceeds limit");
    let mut bytes = vec![0; count];
    input.read_exact(&mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}
pub fn write_message(output: &mut impl Write, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= MAX_MESSAGE, "Host message exceeds limit");
    output.write_all(&(bytes.len() as u32).to_le_bytes())?;
    output.write_all(&bytes)?;
    output.flush()?;
    Ok(())
}

pub fn entry() -> i32 {
    let result = (|| -> Result<()> {
        let config: LoadConfig = read_message(&mut std::io::stdin().lock())?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(run(config))
    })();
    if let Err(error) = result {
        let _ = write_message(
            &mut std::io::stdout().lock(),
            &Ready {
                error: Some(format!("{error:#}")),
                core_pid: None,
            },
        );
        return 1;
    }
    0
}

async fn run(config: LoadConfig) -> Result<()> {
    let directory = std::env::current_exe()?
        .parent()
        .context("Missing host directory")?
        .to_owned();
    let core_path = directory.join(if cfg!(windows) {
        "ThroneCore.exe"
    } else {
        "ThroneCore"
    });
    let nonce: u128 = rand::random();
    #[cfg(windows)]
    let socket_name = format!(
        r"\\.\pipe\googleai-checker-core-{}-{nonce:x}",
        std::process::id()
    );
    #[cfg(unix)]
    let socket_name = directory
        .join(format!("ipc-{nonce:x}"))
        .to_string_lossy()
        .into_owned();

    #[cfg(windows)]
    let mut stream = tokio::net::windows::named_pipe::ServerOptions::new()
        .first_pipe_instance(true)
        .max_instances(1)
        .create(&socket_name)?;
    #[cfg(unix)]
    let listener = tokio::net::UnixListener::bind(&socket_name)?;

    let mut command = Command::new(&core_path);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("THRONE_") {
            command.env_remove(key);
        }
    }
    command
        .env("THRONE_CORE_SOCKET", &socket_name)
        .env("THRONE_CORE_DEBUG", "0");
    let mut core = ManagedProcess::spawn_attached(command, &directory.join("core.log"))?;
    #[cfg(windows)]
    timeout(Duration::from_secs(8), stream.connect()).await??;
    #[cfg(unix)]
    let (mut stream, _) = timeout(Duration::from_secs(8), listener.accept()).await??;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        let mut peer = 0;
        let ok = unsafe {
            windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId(
                stream.as_raw_handle(),
                &mut peer,
            )
        };
        ensure!(
            ok != 0 && peer == core.root_pid(),
            "Unexpected core IPC peer"
        );
    }
    #[cfg(unix)]
    ensure!(
        stream.peer_cred()?.pid().map(|p| p as u32) == Some(core.pid()),
        "Unexpected core IPC peer"
    );
    timeout(
        Duration::from_secs(8),
        wire::call(&mut stream, 1, "Start", &config.encode()?),
    )
    .await??;
    write_message(
        &mut std::io::stdout().lock(),
        &Ready {
            error: None,
            core_pid: Some(core.pid()),
        },
    )?;

    // Parent EOF closes the runtime. Owned jobs/groups also cover abrupt app exit.
    let (tx, mut eof) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let mut byte = [0];
        let _ = std::io::stdin().read(&mut byte);
        let _ = tx.send(());
    });
    loop {
        tokio::select! {
            _ = &mut eof => break,
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                ensure!(core.exit_status()?.is_none(), "ThroneCore stopped unexpectedly");
            }
        }
    }
    let _ = timeout(
        Duration::from_secs(1),
        wire::call(&mut stream, 2, "Stop", &[]),
    )
    .await;
    drop(core);
    #[cfg(unix)]
    let _ = std::fs::remove_file(socket_name);
    Ok(())
}
