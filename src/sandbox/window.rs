use anyhow::{Result, bail};
use windows_sys::Win32::{
    Foundation::{HWND, LPARAM},
    UI::WindowsAndMessaging::{
        EnumWindows, GW_OWNER, GWL_STYLE, GetWindow, GetWindowLongPtrW, GetWindowTextW,
        GetWindowThreadProcessId, IsIconic, IsWindowVisible, SW_HIDE, SW_RESTORE,
        SetForegroundWindow, ShowWindowAsync, WS_CAPTION,
    },
};

// Restrict window operations to the managed root PID and its main captioned
// window. Neither a personal Throne nor a profile editor dialog is a target.
fn main_window(pid: u32) -> Result<Option<HWND>> {
    struct Search {
        pid: u32,
        window: HWND,
    }
    unsafe extern "system" fn inspect(window: HWND, data: LPARAM) -> i32 {
        let search = unsafe { &mut *(data as *mut Search) };
        let mut owner = 0;
        unsafe { GetWindowThreadProcessId(window, &mut owner) };
        if owner == search.pid
            && unsafe { GetWindow(window, GW_OWNER) }.is_null()
            && unsafe { GetWindowLongPtrW(window, GWL_STYLE) } as u32 & WS_CAPTION == WS_CAPTION
        {
            let mut title = [0u16; 1024];
            let len = unsafe { GetWindowTextW(window, title.as_mut_ptr(), title.len() as i32) };
            if len > 0 && String::from_utf16_lossy(&title[..len as usize]).contains("Throne") {
                search.window = window;
            }
        }
        1
    }
    let mut search = Search {
        pid,
        window: std::ptr::null_mut(),
    };
    if unsafe { EnumWindows(Some(inspect), &mut search as *mut _ as LPARAM) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok((!search.window.is_null()).then_some(search.window))
}

pub fn visible(pid: u32) -> Result<bool> {
    Ok(main_window(pid)?
        .is_some_and(|window| unsafe { IsWindowVisible(window) != 0 && IsIconic(window) == 0 }))
}

pub fn set_visible(pid: u32, visible: bool) -> Result<()> {
    let Some(window) = main_window(pid)? else {
        bail!("Окно Throne ещё не готово; повторите нажатие");
    };
    // SW_HIDE never sends WM_CLOSE and cannot stop the proxy, even if the user
    // disables Throne's tray icon. The show path first activates Qt via IPC.
    if unsafe { ShowWindowAsync(window, if visible { SW_RESTORE } else { SW_HIDE }) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if visible {
        unsafe { SetForegroundWindow(window) };
    }
    Ok(())
}

#[cfg(test)]
pub fn close_for_test(pid: u32) -> Result<()> {
    use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_CLOSE};
    let window = main_window(pid)?.ok_or_else(|| anyhow::anyhow!("No Throne window"))?;
    if unsafe { PostMessageW(window, WM_CLOSE, 0, 0) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
