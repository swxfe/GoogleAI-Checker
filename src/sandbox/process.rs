use anyhow::{Context, Result};
use std::{
    fs::File,
    path::Path,
    process::{Child, Command, Stdio},
};

/// Never open the same Throne database in a second running GUI process.
pub fn executable_is_running(executable: &Path) -> Result<bool> {
    let expected = dunce::canonicalize(executable)?;
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::{
            Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
            System::{
                Diagnostics::ToolHelp::{
                    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
                    TH32CS_SNAPPROCESS,
                },
                Threading::{
                    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
                },
            },
        };
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(snapshot, &mut entry);
        let mut found = false;
        while more != 0 {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.th32ProcessID);
            if !handle.is_null() {
                let mut buffer = vec![0u16; 32768];
                let mut size = buffer.len() as u32;
                if QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size) != 0 {
                    let path = std::path::PathBuf::from(String::from_utf16_lossy(
                        &buffer[..size as usize],
                    ));
                    found |= dunce::canonicalize(path).is_ok_and(|path| path == expected);
                }
                CloseHandle(handle);
            }
            if found {
                break;
            }
            more = Process32NextW(snapshot, &mut entry);
        }
        CloseHandle(snapshot);
        Ok(found)
    }
    #[cfg(target_os = "linux")]
    {
        for entry in std::fs::read_dir("/proc")?.flatten() {
            if std::fs::read_link(entry.path().join("exe")).is_ok_and(|p| p == expected) {
                return Ok(true);
            }
        }
        Ok(false)
    }
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("ps").args(["-ax", "-o", "comm="]).output()?;
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| dunce::canonicalize(line.trim()).is_ok_and(|p| p == expected)))
    }
}

pub struct ManagedProcess {
    terminated: bool,
    child: Child,
    #[cfg(windows)]
    job: windows_job::Job,
    #[cfg(unix)]
    group: i32,
}
impl ManagedProcess {
    pub fn spawn(mut command: Command, log: &Path) -> Result<Self> {
        let log = File::options().create(true).append(true).open(log)?;
        command
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        Self::spawn_owned(command, true)
    }
    /// Used inside the owned host: on Unix the core stays in the host's process
    /// group so killing that host also covers its descendants immediately.
    pub fn spawn_attached(mut command: Command, log: &Path) -> Result<Self> {
        let log = File::options().create(true).append(true).open(log)?;
        command
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        Self::spawn_owned(command, false)
    }
    pub fn spawn_piped(mut command: Command, log: &Path) -> Result<Self> {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(File::options().create(true).append(true).open(log)?);
        Self::spawn_owned(command, true)
    }
    pub fn take_stdin(&mut self) -> Option<std::process::ChildStdin> {
        self.child.stdin.take()
    }
    pub fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.stdout.take()
    }
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
    fn spawn_owned(mut command: Command, separate_group: bool) -> Result<Self> {
        #[cfg(windows)]
        {
            let _ = separate_group;
            use std::os::windows::{io::AsRawHandle, process::CommandExt};
            use windows_sys::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED};
            let job = windows_job::Job::new()?;
            command.creation_flags(CREATE_NO_WINDOW | CREATE_SUSPENDED);
            let mut child = command
                .spawn()
                .context("Не удалось запустить дочерний Throne")?;
            if let Err(e) = job.assign_and_resume(child.as_raw_handle(), child.id()) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
            Ok(Self {
                child,
                job,
                terminated: false,
            })
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            if separate_group {
                command.process_group(0);
            }
            let child = command
                .spawn()
                .context("Не удалось запустить дочерний Throne")?;
            let group = if separate_group { child.id() as i32 } else { 0 };
            Ok(Self {
                child,
                group,
                terminated: false,
            })
        }
    }
    #[cfg(test)]
    pub fn id(&self) -> u32 {
        self.child.id()
    }
    #[cfg(windows)]
    pub fn root_pid(&self) -> u32 {
        self.child.id()
    }
    pub fn exit_status(&mut self) -> Result<Option<std::process::ExitStatus>> {
        Ok(self.child.try_wait()?)
    }
    pub fn tree_running(&self) -> bool {
        #[cfg(windows)]
        {
            self.job.running()
        }
        #[cfg(unix)]
        {
            unsafe {
                libc::kill(
                    if self.group > 0 {
                        -self.group
                    } else {
                        self.child.id() as i32
                    },
                    0,
                ) == 0
            }
        }
    }
    pub fn request_close(&self) {
        #[cfg(windows)]
        self.job.close_windows();
        #[cfg(unix)]
        unsafe {
            libc::kill(
                if self.group > 0 {
                    -self.group
                } else {
                    self.child.id() as i32
                },
                libc::SIGTERM,
            );
        }
    }
    pub fn terminate(&mut self) {
        if self.terminated {
            return;
        }
        self.terminated = true;
        #[cfg(windows)]
        self.job.terminate();
        #[cfg(unix)]
        // Each child was started in a new process group. Never kill by executable name.
        unsafe {
            libc::kill(
                if self.group > 0 {
                    -self.group
                } else {
                    self.child.id() as i32
                },
                libc::SIGKILL,
            );
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        #[cfg(windows)]
        for _ in 0..100 {
            if !self.job.running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}
impl Drop for ManagedProcess {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(windows)]
mod windows_job {
    use super::*;
    use anyhow::bail;
    use std::ffi::c_void;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                Thread32Next,
            },
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                SetInformationJobObject, TerminateJobObject,
            },
            Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME},
        },
    };
    pub struct Job(HANDLE);
    // The owned kernel handle has no thread affinity, and is only closed on Drop.
    unsafe impl Send for Job {}
    impl Job {
        pub fn new() -> Result<Self> {
            unsafe {
                let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
                if handle.is_null() {
                    return Err(std::io::Error::last_os_error().into());
                }
                let job = Self(handle);
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                if SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as *const c_void,
                    std::mem::size_of_val(&info) as u32,
                ) == 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
                Ok(job)
            }
        }
        pub fn assign_and_resume(&self, process: HANDLE, pid: u32) -> Result<()> {
            unsafe {
                if AssignProcessToJobObject(self.0, process) == 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if snapshot == INVALID_HANDLE_VALUE {
                    return Err(std::io::Error::last_os_error().into());
                }
                let mut entry: THREADENTRY32 = std::mem::zeroed();
                entry.dwSize = std::mem::size_of_val(&entry) as u32;
                let mut found = false;
                let mut next = Thread32First(snapshot, &mut entry);
                while next != 0 {
                    if entry.th32OwnerProcessID == pid {
                        let thread = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                        if thread.is_null() {
                            CloseHandle(snapshot);
                            return Err(std::io::Error::last_os_error().into());
                        }
                        let resumed = ResumeThread(thread);
                        CloseHandle(thread);
                        if resumed == u32::MAX {
                            CloseHandle(snapshot);
                            return Err(std::io::Error::last_os_error().into());
                        }
                        found = true;
                    }
                    next = Thread32Next(snapshot, &mut entry);
                }
                CloseHandle(snapshot);
                if !found {
                    bail!("Не найден первичный поток дочернего процесса");
                }
                Ok(())
            }
        }
        pub fn terminate(&self) {
            unsafe {
                TerminateJobObject(self.0, 1);
            }
        }
        pub fn running(&self) -> bool {
            use windows_sys::Win32::System::JobObjects::{
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
                QueryInformationJobObject,
            };
            unsafe {
                let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = std::mem::zeroed();
                if QueryInformationJobObject(
                    self.0,
                    JobObjectBasicAccountingInformation,
                    &mut info as *mut _ as *mut c_void,
                    std::mem::size_of_val(&info) as u32,
                    std::ptr::null_mut(),
                ) == 0
                {
                    return true;
                }
                info.ActiveProcesses > 0
            }
        }
        pub fn close_windows(&self) {
            use windows_sys::Win32::{
                Foundation::{HWND, LPARAM},
                System::{
                    JobObjects::IsProcessInJob,
                    Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
                },
                UI::WindowsAndMessaging::{
                    EnumWindows, GetWindowThreadProcessId, IsWindowVisible, PostMessageW, WM_CLOSE,
                },
            };
            unsafe extern "system" fn close(hwnd: HWND, param: LPARAM) -> i32 {
                unsafe {
                    if IsWindowVisible(hwnd) == 0 {
                        return 1;
                    }
                    let job = &*(param as *const Job);
                    let mut pid = 0;
                    GetWindowThreadProcessId(hwnd, &mut pid);
                    let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                    if !process.is_null() {
                        let mut owned = 0;
                        if IsProcessInJob(process, job.0, &mut owned) != 0 && owned != 0 {
                            PostMessageW(hwnd, WM_CLOSE, 0, 0);
                        }
                        CloseHandle(process);
                    }
                    1
                }
            }
            unsafe {
                EnumWindows(Some(close), self as *const _ as LPARAM);
            }
        }
    }
    impl Drop for Job {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn drop_kills_only_owned_process_tree() {
        let dir = tempfile::tempdir().unwrap();
        fn waiting_command() -> Command {
            #[cfg(windows)]
            let command = {
                let mut c = Command::new("cmd.exe");
                c.args(["/D", "/C", "ping -n 60 127.0.0.1 >nul"]);
                c
            };
            #[cfg(unix)]
            let command = {
                let mut c = Command::new("sh");
                c.args(["-c", "sleep 60 & wait"]);
                c
            };
            command
        }
        let mut unrelated =
            ManagedProcess::spawn(waiting_command(), &dir.path().join("unrelated.log")).unwrap();
        let child =
            ManagedProcess::spawn(waiting_command(), &dir.path().join("child.log")).unwrap();
        let pid = child.id();
        assert!(pid > 0);
        std::thread::sleep(std::time::Duration::from_millis(100));
        drop(child);
        assert!(
            unrelated.exit_status().unwrap().is_none(),
            "A different process tree must remain alive"
        );
        #[cfg(windows)]
        {
            use windows_sys::Win32::{
                Foundation::{CloseHandle, WAIT_OBJECT_0},
                System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject},
            };
            unsafe {
                let handle = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
                if !handle.is_null() {
                    assert_eq!(WaitForSingleObject(handle, 2000), WAIT_OBJECT_0);
                    CloseHandle(handle);
                }
            }
        }
        #[cfg(unix)]
        {
            assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
        }
    }
}
