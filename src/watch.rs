use crate::notify::{self, ActiveNotification};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

// CTAPHID Protocol Constants
const TYPE_INIT: u8 = 0x80;
const CTAPHID_MSG: u8 = TYPE_INIT | 0x03; // 0x83
const CTAPHID_KEEPALIVE: u8 = TYPE_INIT | 0x3b; // 0xbb
const STATUS_UPNEEDED: u8 = 0x02;
const U2F_SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TouchEvent {
    Active { source: String, reason: String },
    Inactive { source: String },
}

/// Core touch state coordinator managing desktop notification lifecycle.
pub struct TouchCoordinator {
    active_sources: HashMap<String, String>,
    notification: Option<ActiveNotification>,
}

impl Default for TouchCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl TouchCoordinator {
    pub fn new() -> Self {
        Self {
            active_sources: HashMap::new(),
            notification: None,
        }
    }

    /// Process a state update event from any touch detector (PAM U2F, HIDRAW CTAPHID).
    pub fn handle_event(&mut self, event: TouchEvent) {
        match event {
            TouchEvent::Active { source, reason } => {
                let was_empty = self.active_sources.is_empty();
                self.active_sources.insert(source, reason.clone());

                if was_empty || self.notification.is_none() {
                    match notify::send_touch_notification(&reason) {
                        Ok(notif) => {
                            self.notification = Some(notif);
                        }
                        Err(e) => {
                            eprintln!("conduct: watch: notification error: {}", e);
                        }
                    }
                }
            }
            TouchEvent::Inactive { source } => {
                self.active_sources.remove(&source);
                if self.active_sources.is_empty() {
                    // Dropping ActiveNotification auto-closes notification over D-Bus
                    self.notification = None;
                }
            }
        }
    }

    #[allow(dead_code)]
    pub fn is_active(&self) -> bool {
        !self.active_sources.is_empty()
    }
}

/// Watch PAM U2F touch file (/run/user/$UID/pam-u2f-authpending) using Linux inotify.
pub fn watch_pam_u2f(
    runtime_dir: PathBuf,
    sender: Sender<TouchEvent>,
    running: Arc<AtomicBool>,
) -> io::Result<()> {
    const IN_CREATE: u32 = 0x0000_0100;
    const IN_OPEN: u32 = 0x0000_0020;
    const IN_CLOSE_NOWRITE: u32 = 0x0000_0010;
    const IN_CLOSE_WRITE: u32 = 0x0000_0008;
    const IN_DELETE: u32 = 0x0000_0200;
    const IN_CLOEXEC: i32 = 0x0008_0000;
    const IN_NONBLOCK: i32 = 0x0000_0800;

    let inotify_fd = unsafe { libc::inotify_init1(IN_CLOEXEC | IN_NONBLOCK) };
    if inotify_fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let c_path = std::ffi::CString::new(runtime_dir.to_string_lossy().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let mask = IN_CREATE | IN_OPEN | IN_CLOSE_NOWRITE | IN_CLOSE_WRITE | IN_DELETE;
    let wd = unsafe { libc::inotify_add_watch(inotify_fd, c_path.as_ptr(), mask) };
    if wd < 0 {
        unsafe { libc::close(inotify_fd) };
        return Err(io::Error::last_os_error());
    }

    let mut buf = [0u8; 4096];
    let source_id = "pam-u2f".to_string();

    while running.load(Ordering::Relaxed) {
        let n = unsafe { libc::read(inotify_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

        if n > 0 {
            let mut offset = 0;
            let total = n as usize;

            while offset + 16 <= total {
                let mask = u32::from_ne_bytes(buf[offset + 4..offset + 8].try_into().unwrap());
                let len =
                    u32::from_ne_bytes(buf[offset + 12..offset + 16].try_into().unwrap()) as usize;
                offset += 16;

                if offset + len <= total && len > 0 {
                    let name_bytes = &buf[offset..offset + len];
                    let name = String::from_utf8_lossy(name_bytes)
                        .trim_end_matches('\0')
                        .to_string();
                    offset += len;

                    if name == "pam-u2f-authpending" {
                        if (mask & (IN_OPEN | IN_CREATE)) != 0 {
                            let _ = sender.send(TouchEvent::Active {
                                source: source_id.clone(),
                                reason: "privilege elevation (PAM U2F)".to_string(),
                            });
                        } else if (mask & (IN_CLOSE_NOWRITE | IN_CLOSE_WRITE | IN_DELETE)) != 0 {
                            let _ = sender.send(TouchEvent::Inactive {
                                source: source_id.clone(),
                            });
                        }
                    }
                } else {
                    offset += len;
                }
            }
        } else {
            // Sleep briefly to avoid busy loop when non-blocking
            thread::sleep(Duration::from_millis(50));
        }
    }

    unsafe { libc::close(inotify_fd) };
    Ok(())
}

/// Watch a specific /dev/hidraw device for FIDO/U2F CTAPHID packets requesting user presence.
fn watch_hidraw_device(device_path: PathBuf, sender: Sender<TouchEvent>, running: Arc<AtomicBool>) {
    let Ok(mut file) = File::open(&device_path) else {
        return;
    };

    let source_id = format!("hidraw:{}", device_path.display());
    let mut buf = [0u8; 64];
    let mut is_active = false;
    let mut last_keepalive = Instant::now();

    // Set non-blocking on file descriptor
    let fd = file.as_raw_fd();
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }

    while running.load(Ordering::Relaxed) {
        match file.read(&mut buf) {
            Ok(n) if n >= 9 => {
                let cmd = buf[4];
                let val1 = buf[7];
                let val2 = ((buf[7] as u16) << 8) | (buf[8] as u16);

                let waiting = (cmd == CTAPHID_KEEPALIVE && val1 == STATUS_UPNEEDED)
                    || (cmd == CTAPHID_MSG && val2 == U2F_SW_CONDITIONS_NOT_SATISFIED);

                if waiting {
                    last_keepalive = Instant::now();
                    if !is_active {
                        is_active = true;
                        let _ = sender.send(TouchEvent::Active {
                            source: source_id.clone(),
                            reason: "hardware authentication (FIDO2 / SSH)".to_string(),
                        });
                    }
                }
            }
            Ok(_) | Err(_) => {
                // If waiting was active and no keepalive received within 1500ms, mark inactive
                if is_active && last_keepalive.elapsed() > Duration::from_millis(1500) {
                    is_active = false;
                    let _ = sender.send(TouchEvent::Inactive {
                        source: source_id.clone(),
                    });
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    if is_active {
        let _ = sender.send(TouchEvent::Inactive { source: source_id });
    }
}

/// Discover all current /dev/hidraw devices.
fn find_hidraw_devices() -> Vec<PathBuf> {
    let mut devices = Vec::new();
    let Ok(entries) = fs::read_dir("/dev") else {
        return devices;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("hidraw") {
            let path = Path::new("/dev").join(&name);
            if let Ok(meta) = entry.metadata() {
                if meta.file_type().is_char_device() {
                    devices.push(path);
                }
            }
        }
    }
    devices
}

/// Main entry point for the unified conduct watch daemon.
pub fn run_watch(verbose: bool) -> io::Result<()> {
    println!("conduct: starting unified privilege and touch detection daemon...");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // Catch signals cleanly
    let (sender, receiver): (Sender<TouchEvent>, Receiver<TouchEvent>) = channel();

    // 1. Start PAM U2F inotify watcher
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let uid = unsafe { libc::getuid() };
            PathBuf::from(format!("/run/user/{}", uid))
        });

    if runtime_dir.exists() {
        let pam_sender = sender.clone();
        let pam_running = running.clone();
        let pam_dir = runtime_dir.clone();
        thread::spawn(move || {
            if let Err(e) = watch_pam_u2f(pam_dir, pam_sender, pam_running) {
                eprintln!("conduct: watch: PAM U2F watcher error: {}", e);
            }
        });
        if verbose {
            println!(
                "conduct: monitoring PAM U2F events in {}",
                runtime_dir.display()
            );
        }
    } else {
        eprintln!(
            "conduct: warning: runtime directory {} not found, skipping inotify",
            runtime_dir.display()
        );
    }

    // 2. Start HIDRAW CTAPHID watchers for connected authenticators
    let mut active_devices = HashSet::new();
    for dev in find_hidraw_devices() {
        if active_devices.insert(dev.clone()) {
            let dev_sender = sender.clone();
            let dev_running = running.clone();
            thread::spawn(move || {
                watch_hidraw_device(dev, dev_sender, dev_running);
            });
        }
    }

    if verbose {
        println!(
            "conduct: monitoring {} hidraw devices for CTAPHID keepalive events",
            active_devices.len()
        );
    }

    // 3. Coordinator loop
    let mut coordinator = TouchCoordinator::new();

    println!("conduct: daemon listening for touch requests. Press Ctrl+C to terminate.");

    while r.load(Ordering::Relaxed) {
        match receiver.recv_timeout(Duration::from_millis(500)) {
            Ok(event) => {
                if verbose {
                    println!("conduct: touch event: {:?}", event);
                }
                coordinator.handle_event(event);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Periodic check for newly plugged in hidraw devices
                for dev in find_hidraw_devices() {
                    if active_devices.insert(dev.clone()) {
                        if verbose {
                            println!("conduct: detected new device: {}", dev.display());
                        }
                        let dev_sender = sender.clone();
                        let dev_running = running.clone();
                        thread::spawn(move || {
                            watch_hidraw_device(dev, dev_sender, dev_running);
                        });
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    println!("conduct: daemon exiting cleanly.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_touch_coordinator_state_transitions() {
        let mut coord = TouchCoordinator::new();
        assert!(!coord.is_active());

        // Event from PAM
        coord.handle_event(TouchEvent::Active {
            source: "pam-u2f".to_string(),
            reason: "sudo".to_string(),
        });
        assert!(coord.is_active());

        // Event from HIDRAW (concurrent)
        coord.handle_event(TouchEvent::Active {
            source: "hidraw:5".to_string(),
            reason: "ssh".to_string(),
        });
        assert!(coord.is_active());

        // PAM finishes
        coord.handle_event(TouchEvent::Inactive {
            source: "pam-u2f".to_string(),
        });
        // Still active because hidraw is waiting
        assert!(coord.is_active());

        // HIDRAW finishes
        coord.handle_event(TouchEvent::Inactive {
            source: "hidraw:5".to_string(),
        });
        // Now inactive!
        assert!(!coord.is_active());
    }
}
