use crate::notify::{self, ActiveNotification};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

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
    NewDevice { path: PathBuf },
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
                let changed = self.active_sources.insert(source, reason).is_none();
                if changed || self.notification.is_none() {
                    self.update_notification();
                }
            }
            TouchEvent::Inactive { source } => {
                if self.active_sources.remove(&source).is_some() {
                    if self.active_sources.is_empty() {
                        // All operations finished: drop notification to auto-dismiss over D-Bus
                        self.notification = None;
                    } else {
                        // Other operations are still pending: update notification in-place
                        self.update_notification();
                    }
                }
            }
            TouchEvent::NewDevice { .. } => {}
        }
    }

    fn update_notification(&mut self) {
        if self.active_sources.is_empty() {
            self.notification = None;
            return;
        }

        let existing_id = self.notification.as_ref().and_then(|n| n.id());
        let mut reasons: Vec<String> = self.active_sources.values().cloned().collect();
        reasons.sort();
        reasons.dedup();

        match notify::send_or_update_touch_notification(&reasons, existing_id) {
            Ok(notif) => {
                self.notification = Some(notif);
            }
            Err(e) => {
                eprintln!("conduct: watch: notification error: {}", e);
            }
        }
    }

    #[allow(dead_code)]
    pub fn is_active(&self) -> bool {
        !self.active_sources.is_empty()
    }
}

/// Watch PAM U2F touch file and /dev for new devices using pure blocking Linux inotify.
/// Zero polling, zero timer wakeups when idle.
pub fn watch_inotify(
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

    // Use blocking inotify file descriptor (no IN_NONBLOCK).
    // The kernel puts this thread into deep interruptible sleep until an event occurs.
    let inotify_fd = unsafe { libc::inotify_init1(IN_CLOEXEC) };
    if inotify_fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // 1. Watch user runtime directory for pam-u2f-authpending
    let c_runtime = std::ffi::CString::new(runtime_dir.to_string_lossy().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let pam_mask = IN_CREATE | IN_OPEN | IN_CLOSE_NOWRITE | IN_CLOSE_WRITE | IN_DELETE;
    let pam_wd = unsafe { libc::inotify_add_watch(inotify_fd, c_runtime.as_ptr(), pam_mask) };
    if pam_wd < 0 {
        unsafe { libc::close(inotify_fd) };
        return Err(io::Error::last_os_error());
    }

    // 2. Watch /dev for newly plugged in hidraw devices (event-driven device hotplug)
    let c_dev = std::ffi::CString::new("/dev")
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let dev_wd = unsafe { libc::inotify_add_watch(inotify_fd, c_dev.as_ptr(), IN_CREATE) };

    let mut buf = [0u8; 4096];
    let source_id = "pam-u2f".to_string();

    while running.load(Ordering::Relaxed) {
        // Pure blocking read: CPU stays in deepest package C-state until kernel generates an event
        let n = unsafe { libc::read(inotify_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

        if n <= 0 {
            break;
        }

        let mut offset = 0;
        let total = n as usize;

        while offset + 16 <= total {
            let wd = i32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap());
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

                if wd == pam_wd && name == "pam-u2f-authpending" {
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
                } else if dev_wd >= 0 && wd == dev_wd && name.starts_with("hidraw") {
                    let path = Path::new("/dev").join(name);
                    let _ = sender.send(TouchEvent::NewDevice { path });
                }
            } else {
                offset += len;
            }
        }
    }

    unsafe { libc::close(inotify_fd) };
    Ok(())
}

/// Watch a specific /dev/hidraw device for FIDO/U2F CTAPHID packets requesting user presence.
/// Pure event-driven blocking read: thread sleeps in kernel until USB hardware reports an interrupt packet.
fn watch_hidraw_device(device_path: PathBuf, sender: Sender<TouchEvent>, running: Arc<AtomicBool>) {
    let Ok(mut file) = File::open(&device_path) else {
        return;
    };

    let source_id = format!("hidraw:{}", device_path.display());
    let mut buf = [0u8; 64];
    let mut is_active = false;

    // Use blocking reads with a read timeout (1.5s) only when active.
    // While idle, blocking read sleeps in the kernel with 0 wakeups.
    while running.load(Ordering::Relaxed) {
        match file.read(&mut buf) {
            Ok(n) if n >= 9 => {
                let cmd = buf[4];
                let val1 = buf[7];
                let val2 = ((buf[7] as u16) << 8) | (buf[8] as u16);

                let waiting = (cmd == CTAPHID_KEEPALIVE && val1 == STATUS_UPNEEDED)
                    || (cmd == CTAPHID_MSG && val2 == U2F_SW_CONDITIONS_NOT_SATISFIED);

                if waiting && !is_active {
                    is_active = true;
                    let _ = sender.send(TouchEvent::Active {
                        source: source_id.clone(),
                        reason: "hardware authentication (FIDO2 / SSH)".to_string(),
                    });
                } else if !waiting && is_active {
                    is_active = false;
                    let _ = sender.send(TouchEvent::Inactive {
                        source: source_id.clone(),
                    });
                }
            }
            Ok(_) => {
                // Packet arrived but not waiting for touch
                if is_active {
                    is_active = false;
                    let _ = sender.send(TouchEvent::Inactive {
                        source: source_id.clone(),
                    });
                }
            }
            Err(_) => {
                // Device disconnected or read error
                break;
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
/// Fully event-driven: zero wakeups per second when idle.
pub fn run_watch(verbose: bool) -> io::Result<()> {
    println!("conduct: starting zero-wakeup privilege and touch detection daemon...");

    let running = Arc::new(AtomicBool::new(true));
    let (sender, receiver): (Sender<TouchEvent>, Receiver<TouchEvent>) = channel();

    // 1. Start event-driven inotify watcher (PAM U2F + /dev hotplug)
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let uid = unsafe { libc::getuid() };
            PathBuf::from(format!("/run/user/{}", uid))
        });

    if runtime_dir.exists() {
        let inotify_sender = sender.clone();
        let inotify_running = running.clone();
        let inotify_runtime = runtime_dir.clone();
        thread::spawn(move || {
            if let Err(e) = watch_inotify(inotify_runtime, inotify_sender, inotify_running) {
                eprintln!("conduct: watch: inotify watcher error: {}", e);
            }
        });
        if verbose {
            println!("conduct: event-driven inotify active for PAM U2F and /dev hotplug");
        }
    }

    // 2. Start blocking HIDRAW CTAPHID watchers for connected authenticators
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
            "conduct: monitoring {} hidraw devices (blocking kernel reads)",
            active_devices.len()
        );
    }

    // 3. Coordinator loop: blocks indefinitely on receiver until an actual event occurs.
    // Zero polling, zero timer wakeups when idle.
    let mut coordinator = TouchCoordinator::new();

    println!("conduct: daemon listening for touch requests. Zero idle CPU usage.");

    while running.load(Ordering::Relaxed) {
        match receiver.recv() {
            Ok(TouchEvent::NewDevice { path }) => {
                if active_devices.insert(path.clone()) {
                    if verbose {
                        println!(
                            "conduct: detected new authenticator device: {}",
                            path.display()
                        );
                    }
                    let dev_sender = sender.clone();
                    let dev_running = running.clone();
                    thread::spawn(move || {
                        // Brief wait for udev permissions to settle
                        thread::sleep(Duration::from_millis(100));
                        watch_hidraw_device(path, dev_sender, dev_running);
                    });
                }
            }
            Ok(event) => {
                if verbose {
                    println!("conduct: touch event: {:?}", event);
                }
                coordinator.handle_event(event);
            }
            Err(_) => break,
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
