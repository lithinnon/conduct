use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Detailed information for a single process extracted from /proc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub cmdline: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub uid: Option<u32>,
    pub username: Option<String>,
}

impl ProcessInfo {
    /// Format the full command line or fall back to comm.
    pub fn display_cmdline(&self) -> String {
        if self.cmdline.is_empty() {
            format!("[{}]", self.comm)
        } else {
            self.cmdline.join(" ")
        }
    }
}

/// Resolved context of an elevation request, including ancestry and target command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElevationContext {
    /// The immediate caller invoking askpass (e.g. `sudo` or `ssh`).
    pub direct_caller: ProcessInfo,
    /// The process that spawned the direct caller (e.g. `bash`, `antigravity`, `python`), if found.
    pub origin_caller: Option<ProcessInfo>,
    /// Full chain of ancestor processes from direct caller up towards init.
    pub ancestry: Vec<ProcessInfo>,
    /// The target command being elevated (e.g. extracted from `sudo` arguments).
    pub target_command: Option<String>,
}

impl ElevationContext {
    /// Inspect the parent process (`PPID`) of the current process using system `/proc`.
    pub fn inspect_current_caller() -> io::Result<Self> {
        let ppid = libc_getppid();
        Self::inspect_from_root(Path::new("/proc"), ppid)
    }

    /// Inspect a specific PID using system `/proc`.
    pub fn inspect_pid(pid: u32) -> io::Result<Self> {
        Self::inspect_from_root(Path::new("/proc"), pid)
    }

    /// Inspect a PID with an explicit `/proc` root (enables isolated unit tests).
    pub fn inspect_from_root(proc_root: &Path, start_pid: u32) -> io::Result<Self> {
        let mut ancestry = Vec::new();
        let mut visited = HashSet::new();
        let mut current_pid = start_pid;
        const MAX_DEPTH: usize = 16;

        while current_pid > 1 && ancestry.len() < MAX_DEPTH && visited.insert(current_pid) {
            match read_process_info(proc_root, current_pid) {
                Ok(info) => {
                    let next_pid = info.ppid;
                    ancestry.push(info);
                    if next_pid == 0 || next_pid == current_pid {
                        break;
                    }
                    current_pid = next_pid;
                }
                Err(e) if ancestry.is_empty() => {
                    return Err(e);
                }
                Err(_) => {
                    // Stop ancestry traversal if higher process is inaccessible
                    break;
                }
            }
        }

        if ancestry.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Failed to read process info for PID {}", start_pid),
            ));
        }

        let direct_caller = ancestry[0].clone();
        let origin_caller = ancestry.get(1).cloned();

        let target_command = if direct_caller.comm == "sudo" {
            extract_sudo_target_command(&direct_caller.cmdline)
        } else if !direct_caller.cmdline.is_empty() {
            Some(direct_caller.display_cmdline())
        } else {
            None
        };

        Ok(ElevationContext {
            direct_caller,
            origin_caller,
            ancestry,
            target_command,
        })
    }

    /// Primary actor responsible for requesting elevation.
    pub fn primary_requester(&self) -> &ProcessInfo {
        self.origin_caller.as_ref().unwrap_or(&self.direct_caller)
    }

    /// Concise one-line summary for logging or notifications.
    #[allow(dead_code)]
    pub fn format_summary_line(&self) -> String {
        let requester = self.primary_requester();
        let target = self
            .target_command
            .as_deref()
            .unwrap_or("[unknown command]");
        format!("{} (PID {}) -> {}", requester.comm, requester.pid, target)
    }

    /// Notification body formatted for desktop notifications.
    pub fn format_notification_body(&self) -> String {
        let mut out = String::new();
        let requester = self.primary_requester();

        out.push_str(&format!(
            "Requester: {} (PID {})\n",
            requester.comm, requester.pid
        ));

        if let Some(user) = &requester.username {
            out.push_str(&format!("User: {}\n", user));
        } else if let Some(uid) = requester.uid {
            out.push_str(&format!("UID: {}\n", uid));
        }

        if let Some(target) = &self.target_command {
            out.push_str(&format!("Target: {}\n", target));
        }

        if let Some(cwd) = &requester.cwd {
            out.push_str(&format!("Dir: {}\n", cwd.display()));
        } else if let Some(cwd) = &self.direct_caller.cwd {
            out.push_str(&format!("Dir: {}\n", cwd.display()));
        }

        if self.ancestry.len() > 1 {
            let chain = self
                .ancestry
                .iter()
                .map(|p| format!("{}({})", p.comm, p.pid))
                .collect::<Vec<_>>()
                .join(" ➔ ");
            out.push_str(&format!("Tree: {}", chain));
        }

        out.trim_end().to_string()
    }

    /// Formatted banner suitable for printing to stderr / TTY before password prompt.
    pub fn format_terminal_banner(&self) -> String {
        let requester = self.primary_requester();
        let target = self
            .target_command
            .as_deref()
            .unwrap_or("[unknown command]");
        let cwd_str = requester
            .cwd
            .as_ref()
            .or(self.direct_caller.cwd.as_ref())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "[unknown]".to_string());
        let user_str = requester
            .username
            .as_deref()
            .or(self.direct_caller.username.as_deref())
            .unwrap_or("[unknown]");

        let mut lines = Vec::new();
        lines.push("┌─ [conduct] Privilege Elevation Requested ───────────────────┐".to_string());
        lines.push(format!(
            "│ Requester:   {} (PID {})",
            requester.comm, requester.pid
        ));
        lines.push(format!("│ Command:     {}", target));
        lines.push(format!("│ Working Dir: {}", cwd_str));
        lines.push(format!("│ User:        {}", user_str));

        if self.ancestry.len() > 1 {
            let chain = self
                .ancestry
                .iter()
                .map(|p| format!("{}({})", p.comm, p.pid))
                .collect::<Vec<_>>()
                .join(" ➔ ");
            lines.push(format!("│ Ancestry:    {}", chain));
        }

        lines.push("└─────────────────────────────────────────────────────────────┘".to_string());
        lines.join("\n")
    }
}

/// Fallback wrapper for libc getppid to avoid hard libc dependency in interface.
fn libc_getppid() -> u32 {
    let _ = std::process::id(); // ensure standard library process is loaded
                                // Safely query getppid
    #[cfg(unix)]
    {
        extern "C" {
            fn getppid() -> i32;
        }
        unsafe { getppid() as u32 }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Read process information from `/proc/[pid]`.
pub fn read_process_info(proc_root: &Path, pid: u32) -> io::Result<ProcessInfo> {
    let pid_dir = proc_root.join(pid.to_string());
    if !pid_dir.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("PID directory {} does not exist", pid_dir.display()),
        ));
    }

    // Read comm
    let comm_path = pid_dir.join("comm");
    let comm = fs::read_to_string(&comm_path)
        .map(|s| s.trim_end_matches('\n').to_string())
        .unwrap_or_else(|_| format!("pid_{}", pid));

    // Read cmdline (separated by \0)
    let cmdline_path = pid_dir.join("cmdline");
    let cmdline = match fs::read(&cmdline_path) {
        Ok(bytes) => parse_cmdline_bytes(&bytes),
        Err(_) => Vec::new(),
    };

    // Read cwd link
    let cwd_path = pid_dir.join("cwd");
    let cwd = fs::read_link(&cwd_path).ok();

    // Read status for PPid and Uid
    let status_path = pid_dir.join("status");
    let (ppid, uid) = match fs::read_to_string(&status_path) {
        Ok(content) => parse_status_fields(&content),
        Err(_) => (0, None),
    };

    let username = uid.and_then(resolve_username);

    Ok(ProcessInfo {
        pid,
        ppid,
        comm,
        cmdline,
        cwd,
        uid,
        username,
    })
}

/// Parse /proc/[pid]/cmdline bytes delimited by NUL characters.
pub fn parse_cmdline_bytes(bytes: &[u8]) -> Vec<String> {
    if bytes.is_empty() {
        return Vec::new();
    }
    bytes
        .split(|&b| b == 0)
        .filter(|chunk| !chunk.is_empty())
        .map(|chunk| String::from_utf8_lossy(chunk).trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parse PPid and real Uid from /proc/[pid]/status.
pub fn parse_status_fields(content: &str) -> (u32, Option<u32>) {
    let mut ppid = 0;
    let mut uid = None;

    for line in content.lines() {
        if let Some(val) = line.strip_prefix("PPid:") {
            if let Ok(parsed) = val.trim().parse::<u32>() {
                ppid = parsed;
            }
        } else if let Some(val) = line.strip_prefix("Uid:") {
            // Format: Uid: real effective saved fs
            if let Some(first_uid) = val.split_whitespace().next() {
                if let Ok(parsed) = first_uid.parse::<u32>() {
                    uid = Some(parsed);
                }
            }
        }
    }

    (ppid, uid)
}

/// Extract the target command and its arguments from a `sudo` command line invocation.
pub fn extract_sudo_target_command(args: &[String]) -> Option<String> {
    if args.is_empty() {
        return None;
    }

    let mut idx = 1; // skip "sudo" or argv[0]
    let mut skip_next = false;

    while idx < args.len() {
        if skip_next {
            skip_next = false;
            idx += 1;
            continue;
        }

        let arg = &args[idx];

        if arg == "--" {
            // Everything after -- is the command
            if idx + 1 < args.len() {
                return Some(args[idx + 1..].join(" "));
            }
            return None;
        }

        if arg.starts_with('-') {
            // Options that consume an argument in sudo:
            // -u user, -g group, -p prompt, -h host, -C fd, -r role, -t type, -T timeout, -D dir, -U user
            if matches!(
                arg.as_str(),
                "-u" | "-g" | "-p" | "-h" | "-C" | "-r" | "-t" | "-T" | "-D" | "-U"
            ) {
                skip_next = true;
            }
            idx += 1;
            continue;
        }

        // Found the first non-option argument: this is the target command!
        return Some(args[idx..].join(" "));
    }

    None
}

/// Map a UID to a username by querying /etc/passwd or fallback to $USER.
pub fn resolve_username(uid: u32) -> Option<String> {
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let mut parts = line.split(':');
            let name = parts.next();
            let _pass = parts.next();
            let file_uid = parts.next();

            if let (Some(name), Some(file_uid)) = (name, file_uid) {
                if file_uid.trim().parse::<u32>().ok() == Some(uid) {
                    return Some(name.to_string());
                }
            }
        }
    }

    // Fallback: if matches current user, read env
    if let Ok(current_user) = std::env::var("USER") {
        return Some(current_user);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_parse_cmdline_bytes() {
        let input = b"sudo\0-A\0systemctl\0restart\0nginx\0";
        let parsed = parse_cmdline_bytes(input);
        assert_eq!(parsed, vec!["sudo", "-A", "systemctl", "restart", "nginx"]);

        let empty = b"";
        assert!(parse_cmdline_bytes(empty).is_empty());

        let trailing_nuls = b"bash\0\0\0";
        assert_eq!(parse_cmdline_bytes(trailing_nuls), vec!["bash"]);
    }

    #[test]
    fn test_parse_status_fields() {
        let status =
            "Name:\tsudo\nState:\tS (sleeping)\nPPid:\t42042\nUid:\t1000\t1000\t1000\t1000\n";
        let (ppid, uid) = parse_status_fields(status);
        assert_eq!(ppid, 42042);
        assert_eq!(uid, Some(1000));
    }

    #[test]
    fn test_extract_sudo_target_command() {
        let args = vec![
            "sudo".to_string(),
            "-A".to_string(),
            "nh".to_string(),
            "os".to_string(),
            "switch".to_string(),
        ];
        assert_eq!(
            extract_sudo_target_command(&args),
            Some("nh os switch".to_string())
        );

        let args_with_user = vec![
            "sudo".to_string(),
            "-u".to_string(),
            "root".to_string(),
            "-A".to_string(),
            "systemctl".to_string(),
            "status".to_string(),
        ];
        assert_eq!(
            extract_sudo_target_command(&args_with_user),
            Some("systemctl status".to_string())
        );

        let args_with_dash_dash = vec![
            "sudo".to_string(),
            "-A".to_string(),
            "--".to_string(),
            "rm".to_string(),
            "-rf".to_string(),
            "/tmp/garbage".to_string(),
        ];
        assert_eq!(
            extract_sudo_target_command(&args_with_dash_dash),
            Some("rm -rf /tmp/garbage".to_string())
        );
    }

    #[test]
    fn test_read_process_info_and_ancestry_mock() {
        let dir = tempdir().unwrap();
        let proc_root = dir.path();

        // Mock PID 100: agent (antigravity)
        let pid100 = proc_root.join("100");
        fs::create_dir(&pid100).unwrap();
        File::create(pid100.join("comm"))
            .unwrap()
            .write_all(b"antigravity\n")
            .unwrap();
        File::create(pid100.join("cmdline"))
            .unwrap()
            .write_all(b"antigravity\0run\0")
            .unwrap();
        File::create(pid100.join("status"))
            .unwrap()
            .write_all(b"PPid:\t1\nUid:\t1000\t1000\t1000\t1000\n")
            .unwrap();

        // Mock PID 200: sudo invoked by 100
        let pid200 = proc_root.join("200");
        fs::create_dir(&pid200).unwrap();
        File::create(pid200.join("comm"))
            .unwrap()
            .write_all(b"sudo\n")
            .unwrap();
        File::create(pid200.join("cmdline"))
            .unwrap()
            .write_all(b"sudo\0-A\0nixos-rebuild\0switch\0")
            .unwrap();
        File::create(pid200.join("status"))
            .unwrap()
            .write_all(b"PPid:\t100\nUid:\t1000\t0\t0\t0\n")
            .unwrap();

        let ctx = ElevationContext::inspect_from_root(proc_root, 200).unwrap();
        assert_eq!(ctx.direct_caller.comm, "sudo");
        assert_eq!(ctx.direct_caller.pid, 200);

        let origin = ctx.origin_caller.as_ref().unwrap();
        assert_eq!(origin.comm, "antigravity");
        assert_eq!(origin.pid, 100);

        assert_eq!(ctx.target_command, Some("nixos-rebuild switch".to_string()));

        let body = ctx.format_notification_body();
        assert!(body.contains("Requester: antigravity (PID 100)"));
        assert!(body.contains("Target: nixos-rebuild switch"));
        assert!(body.contains("sudo(200) ➔ antigravity(100)"));

        let banner = ctx.format_terminal_banner();
        assert!(banner.contains("Requester:   antigravity (PID 100)"));
        assert!(banner.contains("Command:     nixos-rebuild switch"));
    }
}
