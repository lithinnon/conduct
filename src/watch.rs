use crate::notify::{self, ActiveNotification};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
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

// HID Report Descriptor ioctls & constants
const HIDIOCGRDESCSIZE: libc::c_ulong = 0x8004_4801;
const HIDIOCGRDESC: libc::c_ulong = 0x9004_4802;

const FIDO_USAGE_PAGE: u16 = 0xf1d0;
const FIDO_USAGE_CTAPHID: u8 = 0x01;
const HID_ITEM_TYPE_GLOBAL: u8 = 1;
const HID_ITEM_TYPE_LOCAL: u8 = 2;
const HID_GLOBAL_ITEM_TAG_USAGE_PAGE: u8 = 0;
const HID_LOCAL_ITEM_TAG_USAGE: u8 = 0;

#[repr(C)]
struct HidrawReportDescriptor {
    size: u32,
    value: [u8; 4096],
}

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

/// Inspect the HID report descriptor of a /dev/hidraw device to verify if it is a
/// dedicated FIDO CTAPHID authenticator interface (FIDO_USAGE_PAGE 0xf1d0 & FIDO_USAGE_CTAPHID 0x01).
/// This filters out non-FIDO devices (keyboards, mice, trackpads, OTP keyboards).
pub fn is_fido_device(path: &Path) -> bool {
    let Ok(file) = File::open(path) else {
        return false;
    };
    let fd = file.as_raw_fd();

    let mut desc_size: u32 = 0;
    if unsafe { libc::ioctl(fd, HIDIOCGRDESCSIZE, &mut desc_size) } < 0 {
        return false;
    }

    if desc_size == 0 || desc_size > 4096 {
        return false;
    }

    let mut desc = HidrawReportDescriptor {
        size: desc_size,
        value: [0u8; 4096],
    };

    if unsafe { libc::ioctl(fd, HIDIOCGRDESC, &mut desc) } < 0 {
        return false;
    }

    let mut is_fido = false;
    let mut has_u2f = false;
    let mut i = 0;
    let size = desc.size as usize;

    while i < size {
        let prefix = desc.value[i];
        let tag = (prefix & 0b1111_0000) >> 4;
        let typ = (prefix & 0b0000_1100) >> 2;
        let mut item_size = (prefix & 0b0000_0011) as usize;
        if item_size == 3 {
            item_size = 4;
        }

        if i + 1 < size {
            let val1b = desc.value[i + 1];
            let val2b = if i + 2 < size {
                (val1b as u16) | ((desc.value[i + 2] as u16) << 8)
            } else {
                val1b as u16
            };

            if typ == HID_ITEM_TYPE_GLOBAL
                && tag == HID_GLOBAL_ITEM_TAG_USAGE_PAGE
                && val2b == FIDO_USAGE_PAGE
            {
                is_fido = true;
            } else if typ == HID_ITEM_TYPE_LOCAL
                && tag == HID_LOCAL_ITEM_TAG_USAGE
                && val1b == FIDO_USAGE_CTAPHID
            {
                has_u2f = true;
            }
        }

        if is_fido && has_u2f {
            return true;
        }

        i += item_size + 1;
    }

    false
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

/// Watch a specific /dev/hidraw FIDO device for CTAPHID packets requesting user presence.
/// Pure event-driven kernel syscalls via libc::poll:
/// - When idle: blocks indefinitely (timeout = -1) with 0.00 Hz wakeups.
/// - When active: debounces 100ms keepalives with a 2.0s holdoff and 250ms completion holdoff,
///   completely eliminating desktop notification flapping / seizures.
fn watch_hidraw_device(device_path: PathBuf, sender: Sender<TouchEvent>, running: Arc<AtomicBool>) {
    let Ok(mut file) = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&device_path)
    else {
        return;
    };

    let raw_fd = file.as_raw_fd();
    let source_id = format!("hidraw:{}", device_path.display());
    let mut buf = [0u8; 64];
    let mut is_active = false;
    let mut poll_timeout_ms: i32 = -1; // Infinite wait while idle

    let mut poll_fds = [libc::pollfd {
        fd: raw_fd,
        events: libc::POLLIN,
        revents: 0,
    }];

    while running.load(Ordering::Relaxed) {
        let ret = unsafe {
            libc::poll(
                poll_fds.as_mut_ptr(),
                poll_fds.len() as libc::nfds_t,
                poll_timeout_ms,
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }

        // Timeout expired: no keepalive or trailing packets arrived within the window
        if ret == 0 {
            if is_active {
                is_active = false;
                let _ = sender.send(TouchEvent::Inactive {
                    source: source_id.clone(),
                });
            }
            poll_timeout_ms = -1; // Reset to infinite blocking kernel sleep
            continue;
        }

        let revents = poll_fds[0].revents;
        if (revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
            break;
        }

        if (revents & libc::POLLIN) != 0 {
            match file.read(&mut buf) {
                Ok(n) if n >= 9 => {
                    let cmd = buf[4];
                    let val1 = buf[7];
                    let val2 = ((buf[7] as u16) << 8) | (buf[8] as u16);

                    let waiting = (cmd == CTAPHID_KEEPALIVE && val1 == STATUS_UPNEEDED)
                        || (cmd == CTAPHID_MSG && val2 == U2F_SW_CONDITIONS_NOT_SATISFIED);

                    if waiting {
                        if !is_active {
                            is_active = true;
                            let _ = sender.send(TouchEvent::Active {
                                source: source_id.clone(),
                                reason: "hardware authentication (FIDO2 / SSH)".to_string(),
                            });
                        }
                        // Refresh holdoff window: 2000ms until next expected keepalive
                        poll_timeout_ms = 2000;
                    } else if is_active {
                        // Non-waiting packet while active (e.g. response payload upon touch):
                        // Hold active for 250ms to swallow any trailing continuation packets
                        poll_timeout_ms = 250;
                    }
                }
                Ok(_) => {
                    if is_active {
                        poll_timeout_ms = 250;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(_) => {
                    break;
                }
            }
        }
    }

    if is_active {
        let _ = sender.send(TouchEvent::Inactive { source: source_id });
    }
}

/// Discover all current /dev/hidraw FIDO authenticators.
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
                if meta.file_type().is_char_device() && is_fido_device(&path) {
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
            let dev_path = dev.clone();
            thread::spawn(move || {
                watch_hidraw_device(dev_path, dev_sender, dev_running);
            });
        }
    }

    if verbose {
        println!(
            "conduct: monitoring {} genuine FIDO hidraw devices (blocking kernel reads)",
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
                let dev_sender = sender.clone();
                let dev_running = running.clone();
                let dev_path = path.clone();
                thread::spawn(move || {
                    // Brief wait for udev permissions and ACLs to settle
                    thread::sleep(Duration::from_millis(150));
                    if is_fido_device(&dev_path) {
                        watch_hidraw_device(dev_path, dev_sender, dev_running);
                    }
                });
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
            source: "hidraw:6".to_string(),
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
            source: "hidraw:6".to_string(),
        });
        // Now inactive!
        assert!(!coord.is_active());
    }

    #[test]
    fn test_touch_coordinator_deduplication() {
        let mut coord = TouchCoordinator::new();

        // Repeated active events from keepalive packets for same source
        coord.handle_event(TouchEvent::Active {
            source: "hidraw:6".to_string(),
            reason: "ssh".to_string(),
        });
        coord.handle_event(TouchEvent::Active {
            source: "hidraw:6".to_string(),
            reason: "ssh".to_string(),
        });
        assert!(coord.is_active());
        assert_eq!(coord.active_sources.len(), 1);

        coord.handle_event(TouchEvent::Inactive {
            source: "hidraw:6".to_string(),
        });
        assert!(!coord.is_active());
        assert_eq!(coord.active_sources.len(), 0);
    }
}
