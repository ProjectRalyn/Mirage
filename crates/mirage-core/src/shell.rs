use crate::persona::PrebakedPersona;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

/// Result of executing a command line inside the zero-overhead in-memory Fake Shell.
#[derive(Debug, Clone)]
pub struct ShellExecResult {
    /// Text output to write back to the attacker's terminal (normalized with `\n`).
    pub output: String,
    /// Suggested artificial delay (in ms) before returning the output to waste attacker time.
    pub delay_ms: u64,
    /// Any malware download URLs, C2 endpoints, or dropped file contents captured.
    pub captured_indicators: Vec<String>,
    /// True if the attacker executed `exit` or `logout`.
    pub should_exit: bool,
}

/// Lightweight in-memory state machine simulating a full Ubuntu 22.04 LTS interactive bash shell.
/// Uses a bounded Copy-on-Write (CoW) overlay on top of the shared `PrebakedPersona` template
/// so each session costs <2 KB of RAM and never touches the host OS filesystem or processes.
#[derive(Debug, Clone)]
pub struct FakeShellSession {
    persona: Arc<PrebakedPersona>,
    user: String,
    cwd: String,
    client_ip: String,
    os_is_arch: bool,
    last_exit_code: i32,
    env_vars: HashMap<String, String>,
    /// Bounded Copy-on-Write file overlay (max 16 files, 8 KB total) so attackers can write
    /// `~/.ssh/authorized_keys` or `/tmp/bot.sh` and read them back realistically.
    cow_files: HashMap<String, String>,
    cow_total_bytes: usize,
    history: Vec<String>,
}

const MAX_COW_FILES: usize = 16;
const MAX_COW_BYTES: usize = 8192;

impl FakeShellSession {
    pub fn new(persona: Arc<PrebakedPersona>, login_user: Option<&str>) -> Self {
        let user = login_user
            .filter(|u| !u.trim().is_empty())
            .map(|u| u.to_string())
            .unwrap_or_else(|| persona.ssh_vfs.default_user.clone());
        let home = if user == "root" {
            "/root".to_string()
        } else {
            format!("/home/{}", persona.ssh_vfs.default_user)
        };
        let history = persona
            .ssh_vfs
            .files
            .get(&format!("/home/{}/.bash_history", persona.ssh_vfs.default_user))
            .map(|h| h.lines().map(|l| l.to_string()).collect())
            .unwrap_or_default();

        let mut env_vars = HashMap::new();
        env_vars.insert("USER".to_string(), user.clone());
        env_vars.insert("LOGNAME".to_string(), user.clone());
        env_vars.insert("HOME".to_string(), home.clone());
        env_vars.insert("HOSTNAME".to_string(), persona.hostname.clone());
        env_vars.insert("SHELL".to_string(), "/bin/bash".to_string());
        env_vars.insert("TERM".to_string(), "xterm-256color".to_string());
        env_vars.insert(
            "PATH".to_string(),
            "/opt/conda/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                .to_string(),
        );
        env_vars.insert(
            "CUDA_VISIBLE_DEVICES".to_string(),
            "0,1,2,3,4,5,6,7".to_string(),
        );

        Self {
            persona,
            user,
            cwd: home,
            client_ip: "10.240.0.5".to_string(),
            os_is_arch: false,
            last_exit_code: 0,
            env_vars,
            cow_files: HashMap::new(),
            cow_total_bytes: 0,
            history,
        }
    }

    /// Align OS personality (MOTD, `uname`, `/etc/os-release`, `who`) with the cached SSH banner & client IP.
    pub fn with_session_context(mut self, server_banner: &str, client_ip: std::net::IpAddr) -> Self {
        self.client_ip = client_ip.to_string();
        let lower = server_banner.to_ascii_lowercase();
        if !lower.contains("ubuntu") && !lower.contains("debian") && lower.contains("openssh_10") {
            self.os_is_arch = true;
        }
        self
    }

    pub fn welcome_banner(&self) -> String {
        if self.os_is_arch {
            let (ts, _, _, _) = current_utc_hms();
            format!("Last login: {ts} UTC from {}\r\n", self.client_ip)
        } else {
            self.persona.ssh_vfs.motd.clone()
        }
    }

    pub fn prompt(&self) -> String {
        let home_prefix = if self.user == "root" {
            "/root".to_string()
        } else {
            format!("/home/{}", self.persona.ssh_vfs.default_user)
        };
        let display_cwd = if self.cwd == home_prefix {
            "~".to_string()
        } else if let Some(rel) = self.cwd.strip_prefix(&format!("{home_prefix}/")) {
            format!("~/{rel}")
        } else {
            self.cwd.clone()
        };
        let symbol = if self.user == "root" { "#" } else { "$" };
        format!("{}@{}:{}{} ", self.user, self.persona.hostname, display_cwd, symbol)
    }

    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// Simple tab completion for interactive SSH sessions.
    pub fn tab_complete(&self, current_line: &str) -> Option<String> {
        let token = current_line.split_whitespace().last()?;
        if token.is_empty() {
            return None;
        }
        // Complete commands if first token
        if !current_line.trim_start().contains(' ') {
            const CMDS: &[&str] = &[
                "cat", "cd", "chmod", "chown", "clear", "cp", "crontab", "curl", "date", "df",
                "dmesg", "docker", "du", "echo", "env", "exit", "export", "find", "free", "git",
                "grep", "head", "history", "hostname", "hostnamectl", "id", "ifconfig", "ip",
                "iptables", "journalctl", "kubectl", "last", "ls", "lsb_release", "lsblk",
                "lscpu", "lspci", "mkdir", "mount", "mv", "netstat", "nvidia-smi", "ping", "ps",
                "psql", "pwd", "python3", "redis-cli", "rm", "service", "ss", "stat", "sudo",
                "systemctl", "tail", "tar", "top", "touch", "uname", "uptime", "w", "wc", "wget",
                "which", "whoami",
            ];
            for &cmd in CMDS {
                if let Some(rest) = cmd.strip_prefix(token) {
                    if !rest.is_empty() {
                        return Some(format!("{rest} "));
                    }
                }
            }
        }
        // Complete files in current working directory
        if let Some(entries) = self.persona.ssh_vfs.directories.get(&self.cwd) {
            for entry in entries {
                if let Some(rest) = entry.strip_prefix(token) {
                    if !rest.is_empty() {
                        return Some(rest.to_string());
                    }
                }
            }
        }
        None
    }

    /// Execute a full command line (supports `;`, `&&`, pipes `|`, env expansion `$VAR`, and `>` / `>>` redirection).
    pub fn execute_line(&mut self, raw_line: &str) -> ShellExecResult {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            return ShellExecResult {
                output: String::new(),
                delay_ms: 0,
                captured_indicators: Vec::new(),
                should_exit: false,
            };
        }

        self.history.push(line.to_string());

        let mut combined_output = Vec::new();
        let mut total_delay_ms = 0u64;
        let mut captured_indicators = Vec::new();
        let mut should_exit = false;

        for subcmd in split_chained_commands(line) {
            let subcmd = subcmd.trim();
            if subcmd.is_empty() {
                continue;
            }
            let res = self.execute_pipeline_and_redirection(subcmd);
            if !res.output.is_empty() {
                combined_output.push(res.output);
            }
            total_delay_ms = total_delay_ms.saturating_add(res.delay_ms);
            captured_indicators.extend(res.captured_indicators);
            if res.should_exit {
                should_exit = true;
                break;
            }
        }

        let mut final_output = combined_output.join("\n");
        if !final_output.is_empty() && !final_output.ends_with('\n') {
            final_output.push('\n');
        }

        ShellExecResult {
            output: final_output,
            delay_ms: total_delay_ms.min(8000),
            captured_indicators,
            should_exit,
        }
    }

    fn execute_pipeline_and_redirection(&mut self, cmd_line: &str) -> ShellExecResult {
        // Strip trailing `2>&1` or `2>/dev/null`
        let cleaned = cmd_line
            .replace("2>&1", "")
            .replace("2>/dev/null", "")
            .replace("&>/dev/null", "");
        let cleaned = cleaned.trim();

        // Check for output redirection `>>` or `>`
        let (pipeline_part, redirect_target) = parse_redirection(cleaned);

        // Split pipeline by `|`
        let stages: Vec<&str> = pipeline_part.split('|').map(|s| s.trim()).collect();
        if stages.is_empty() {
            return ShellExecResult {
                output: String::new(),
                delay_ms: 0,
                captured_indicators: Vec::new(),
                should_exit: false,
            };
        }

        let expanded_first = self.expand_variables(stages[0]);
        let mut res = self.execute_single(&expanded_first, None, stages.len() > 1);

        for (idx, &stage) in stages[1..].iter().enumerate() {
            let expanded_stage = self.expand_variables(stage);
            let has_more_pipes = idx + 2 < stages.len();
            let next_res = self.execute_single(&expanded_stage, Some(&res.output), has_more_pipes);
            res.output = next_res.output;
            res.delay_ms = res.delay_ms.saturating_add(next_res.delay_ms);
            res.captured_indicators.extend(next_res.captured_indicators);
            if next_res.should_exit {
                res.should_exit = true;
                break;
            }
        }

        if let Some((target_file, is_append)) = redirect_target {
            let resolved = self.resolve_path(target_file);
            if resolved != "/dev/null" {
                self.write_cow_file(&resolved, &res.output, is_append);
                res.captured_indicators
                    .push(format!("file_write:{resolved} ({} bytes)", res.output.len()));
            }
            res.output.clear();
        }

        res
    }

    fn expand_variables(&self, input: &str) -> String {
        if !input.contains('$') {
            return input.to_string();
        }
        let mut out = input.replace("$?", &self.last_exit_code.to_string());
        out = out.replace("$PWD", &self.cwd);
        out = out.replace("${PWD}", &self.cwd);
        for (k, v) in &self.env_vars {
            out = out.replace(&format!("${{{k}}}"), v);
            out = out.replace(&format!("${k}"), v);
        }
        out
    }

    fn read_vfs_file(&self, resolved_path: &str) -> Option<String> {
        if let Some(cow) = self.cow_files.get(resolved_path) {
            return Some(cow.clone());
        }
        if self.os_is_arch && resolved_path == "/etc/os-release" {
            return Some(
                "NAME=\"Arch Linux\"\nPRETTY_NAME=\"Arch Linux\"\nID=arch\nBUILD_ID=rolling\nANSI_COLOR=\"38;2;23;147;209\"\n"
                    .to_string(),
            );
        }
        if resolved_path == "/proc/version" {
            return Some(if self.os_is_arch {
                "Linux version 6.12.9-arch1-1 (linux@archlinux) (gcc (GCC) 14.2.1 20250110, GNU ld (GNU Binutils) 2.43.1) #1 SMP PREEMPT_DYNAMIC\n".to_string()
            } else {
                "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-045) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0) #101-Ubuntu SMP\n".to_string()
            });
        }
        if resolved_path == "/proc/uptime" {
            return Some("3591248.42 14310291.18\n".to_string());
        }
        if resolved_path == "/proc/loadavg" {
            return Some("1.42 1.38 1.29 2/418 19402\n".to_string());
        }
        self.persona.ssh_vfs.files.get(resolved_path).cloned()
    }

    fn write_cow_file(&mut self, resolved_path: &str, content: &str, append: bool) {
        if self.cow_files.len() >= MAX_COW_FILES && !self.cow_files.contains_key(resolved_path) {
            return;
        }
        let existing = if append {
            self.read_vfs_file(resolved_path).unwrap_or_default()
        } else {
            String::new()
        };
        let mut new_content = if existing.is_empty() {
            content.to_string()
        } else {
            format!("{}\n{}", existing.trim_end_matches('\n'), content)
        };
        if new_content.len() > 2048 {
            new_content.truncate(2048);
        }
        if self.cow_total_bytes + new_content.len() <= MAX_COW_BYTES {
            self.cow_total_bytes += new_content.len();
            self.cow_files.insert(resolved_path.to_string(), new_content);
        }
    }

    fn execute_single(
        &mut self,
        cmd_line: &str,
        stdin_input: Option<&str>,
        is_piped_out: bool,
    ) -> ShellExecResult {
        // Handle inline `VAR=val` assignment or `export VAR=val`
        let parts: Vec<&str> = cmd_line.split_whitespace().collect();
        if parts.is_empty() {
            return ShellExecResult {
                output: String::new(),
                delay_ms: 0,
                captured_indicators: Vec::new(),
                should_exit: false,
            };
        }

        let prog = parts[0];
        let args = &parts[1..];

        // Check bare `VAR=val` assignment
        if !prog.starts_with('/') && prog.contains('=') && args.is_empty() {
            if let Some((k, v)) = prog.split_once('=') {
                self.env_vars
                    .insert(k.to_string(), v.trim_matches('"').trim_matches('\'').to_string());
                self.last_exit_code = 0;
                return ShellExecResult {
                    output: String::new(),
                    delay_ms: 10,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                };
            }
        }

        self.last_exit_code = 0;

        match prog {
            "exit" | "logout" | "quit" => ShellExecResult {
                output: "logout".to_string(),
                delay_ms: 0,
                captured_indicators: Vec::new(),
                should_exit: true,
            },
            "clear" | "reset" => ShellExecResult {
                output: "\x1b[2J\x1b[H".to_string(),
                delay_ms: 10,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "true" | ":" => ShellExecResult {
                output: String::new(),
                delay_ms: 10,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "false" => {
                self.last_exit_code = 1;
                ShellExecResult {
                    output: String::new(),
                    delay_ms: 10,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "id" => {
                let (uid, gid) = if self.user == "root" {
                    (0, 0)
                } else {
                    (1000, 1000)
                };
                ShellExecResult {
                    output: format!(
                        "uid={uid}({user}) gid={gid}({user}) groups={gid}({user}),27(sudo),44(video),998(docker)",
                        user = self.user
                    ),
                    delay_ms: 30,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "whoami" => ShellExecResult {
                output: self.user.clone(),
                delay_ms: 20,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "groups" => ShellExecResult {
                output: format!("{} sudo video docker", self.user),
                delay_ms: 20,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "w" => {
                let (_, h, m, _) = current_utc_hms();
                ShellExecResult {
                    output: format!(
                        " {h:02}:{m:02}:00 up 41 days, 18:12,  1 user,  load average: 1.42, 1.38, 1.29\n\
                         USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n\
                         {:<8} pts/0    {:<16} {h:02}:{m:02}    0.00s  0.02s  0.00s -bash",
                        self.user, self.client_ip
                    ),
                    delay_ms: 40,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "who" => {
                let (ts, _, _, _) = current_utc_hms();
                ShellExecResult {
                    output: format!(
                        "{:<8} pts/0        {} ({})",
                        self.user,
                        &ts[..16],
                        self.client_ip
                    ),
                    delay_ms: 30,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "last" | "lastlog" => ShellExecResult {
                output: self.persona.ssh_vfs.last_output.clone(),
                delay_ms: 50,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "hostname" => {
                let out = if args.contains(&"-I") || args.contains(&"-i") {
                    format!("{} 172.17.0.1", self.persona.internal_ip)
                } else if args.contains(&"-f") {
                    format!("{}.internal.corp", self.persona.hostname)
                } else {
                    self.persona.hostname.clone()
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 25,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "hostnamectl" => {
                let (os_name, kernel_ver) = if self.os_is_arch {
                    ("Arch Linux", "Linux 6.12.9-arch1-1")
                } else {
                    ("Ubuntu 22.04.3 LTS", "Linux 5.15.0-91-generic")
                };
                ShellExecResult {
                    output: format!(
                        " Static hostname: {host}\n\
                         \x20      Icon name: computer-server\n\
                         \x20        Chassis: server\n\
                         \x20     Machine ID: 9f4b2c8e1a7d3065b8e2f1c4a9d0731e\n\
                         \x20        Boot ID: 4a1c8e9d2b7410a9f8a7c2e1b4d603f5\n\
                         Operating System: {os_name}\n\
                         \x20         Kernel: {kernel_ver}\n\
                         \x20   Architecture: x86-64\n\
                         \x20Hardware Vendor: Supermicro\n\
                         \x20 Hardware Model: AS-8125GS-TNHR",
                        host = self.persona.hostname
                    ),
                    delay_ms: 45,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "lsb_release" => {
                if self.os_is_arch {
                    self.last_exit_code = 127;
                    ShellExecResult {
                        output: "bash: lsb_release: command not found".to_string(),
                        delay_ms: 25,
                        captured_indicators: Vec::new(),
                        should_exit: false,
                    }
                } else {
                    ShellExecResult {
                        output: "No LSB modules are available.\n\
                                 Distributor ID:\tUbuntu\n\
                                 Description:\tUbuntu 22.04.3 LTS\n\
                                 Release:\t22.04\n\
                                 Codename:\tjammy"
                            .to_string(),
                        delay_ms: 35,
                        captured_indicators: Vec::new(),
                        should_exit: false,
                    }
                }
            }
            "pwd" => ShellExecResult {
                output: self.cwd.clone(),
                delay_ms: 15,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "uname" => {
                let (full_uname, rel) = if self.os_is_arch {
                    (
                        format!(
                            "Linux {} 6.12.9-arch1-1 #1 SMP PREEMPT_DYNAMIC Fri, 10 Jan 2025 14:22:10 +0000 x86_64 GNU/Linux",
                            self.persona.hostname
                        ),
                        "6.12.9-arch1-1".to_string(),
                    )
                } else {
                    (
                        self.persona.ssh_vfs.kernel_uname.clone(),
                        self.persona.ssh_vfs.kernel_release.clone(),
                    )
                };
                let out = if args.iter().any(|a| a.contains('a')) {
                    full_uname
                } else if args.iter().any(|a| a.contains('r')) {
                    rel
                } else if args.iter().any(|a| a.contains('n')) {
                    self.persona.hostname.clone()
                } else if args.iter().any(|a| a.contains('m')) {
                    "x86_64".to_string()
                } else {
                    "Linux".to_string()
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 25,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "lscpu" => ShellExecResult {
                output: self.persona.ssh_vfs.lscpu_output.clone(),
                delay_ms: 40,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "lspci" => ShellExecResult {
                output: self.persona.ssh_vfs.lspci_output.clone(),
                delay_ms: 50,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "lsblk" => ShellExecResult {
                output: self.persona.ssh_vfs.lsblk_output.clone(),
                delay_ms: 40,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "mount" | "findmnt" => ShellExecResult {
                output: self.persona.ssh_vfs.mount_output.clone(),
                delay_ms: 35,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "dmesg" => ShellExecResult {
                output: self.persona.ssh_vfs.dmesg_output.clone(),
                delay_ms: 60,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "nvidia-smi" => {
                let out = if args.contains(&"-L") {
                    "GPU 0: NVIDIA H100 80GB HBM3 (UUID: GPU-9f4b2c8e-1a7d-3065-b8e2-f1c4a9d00000)\n\
                     GPU 1: NVIDIA H100 80GB HBM3 (UUID: GPU-9f4b2c8e-1a7d-3065-b8e2-f1c4a9d00001)\n\
                     GPU 2: NVIDIA H100 80GB HBM3 (UUID: GPU-9f4b2c8e-1a7d-3065-b8e2-f1c4a9d00002)\n\
                     GPU 3: NVIDIA H100 80GB HBM3 (UUID: GPU-9f4b2c8e-1a7d-3065-b8e2-f1c4a9d00003)"
                        .to_string()
                } else {
                    self.persona.ssh_vfs.nvidia_smi_output.clone()
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 280,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "ps" => ShellExecResult {
                output: self.persona.ssh_vfs.ps_aux_output.clone(),
                delay_ms: 80,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "top" | "htop" => ShellExecResult {
                output: self.persona.ssh_vfs.top_output.clone(),
                delay_ms: 150,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "pgrep" => {
                let pattern = args.last().copied().unwrap_or("python");
                let mut pids = Vec::new();
                for line in self.persona.ssh_vfs.ps_aux_output.lines().skip(1) {
                    if line.contains(pattern) {
                        if let Some(pid) = line.split_whitespace().nth(1) {
                            pids.push(pid);
                        }
                    }
                }
                ShellExecResult {
                    output: pids.join("\n"),
                    delay_ms: 40,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "systemctl" => {
                let out = if args.contains(&"status") {
                    let raw_unit = args
                        .iter()
                        .copied()
                        .find(|a| !a.starts_with('-') && *a != "status")
                        .unwrap_or("sshd");
                    let unit_norm = raw_unit.strip_suffix(".service").unwrap_or(raw_unit);
                    let known = matches!(
                        unit_norm,
                        "ssh" | "sshd" | "docker" | "containerd" | "postgresql" | "redis" | "redis-server" | "nginx"
                    );
                    if !known {
                        self.last_exit_code = 4;
                        format!("Unit {unit_norm}.service could not be found.")
                    } else {
                        let (unit_file, desc, bin) = match unit_norm {
                            "ssh" | "sshd" => (
                                if self.os_is_arch { "sshd.service" } else { "ssh.service" },
                                "OpenBSD Secure Shell server",
                                "/usr/sbin/sshd -D [listener] 0 of 10-100 startups",
                            ),
                            "docker" => ("docker.service", "Docker Application Container Engine", "/usr/bin/dockerd -H fd://"),
                            "postgresql" => ("postgresql.service", "PostgreSQL RDBMS", "/usr/lib/postgresql/14/bin/postgres"),
                            "redis" | "redis-server" => ("redis-server.service", "Advanced key-value store", "/usr/bin/redis-server 127.0.0.1:6379"),
                            "nginx" => ("nginx.service", "A high performance web server", "/usr/sbin/nginx -g daemon on;"),
                            _ => ("containerd.service", "containerd container runtime", "/usr/bin/containerd"),
                        };
                        format!(
                            "● {unit_file} - {desc}\n\
                             \x20    Loaded: loaded (/usr/lib/systemd/system/{unit_file}; enabled; preset: enabled)\n\
                             \x20    Active: active (running) since Wed 2026-10-12 03:14:00 UTC; 41 days ago\n\
                             \x20  Main PID: 842 (sshd)\n\
                             \x20     Tasks: 1 (limit: 614400)\n\
                             \x20    Memory: 14.2M\n\
                             \x20       CPU: 2.418s\n\
                             \x20    CGroup: /system.slice/{unit_file}\n\
                             \x20            └─842 {bin}"
                        )
                    }
                } else {
                    self.persona.ssh_vfs.systemctl_output.clone()
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 70,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "service" => {
                let svc = args.first().copied().unwrap_or("ssh");
                ShellExecResult {
                    output: format!(" * {svc} is running"),
                    delay_ms: 50,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "journalctl" => ShellExecResult {
                output: format!(
                    "Nov 22 03:12:44 {host} sshd[19402]: Accepted publickey for {user} from 10.240.0.5 port 54120 ssh2\n\
                     Nov 22 04:00:01 {host} CRON[19810]: ({user}) CMD (/usr/bin/python3 /opt/deploy/sync_vault.py)",
                    host = self.persona.hostname,
                    user = self.user
                ),
                delay_ms: 80,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "netstat" | "ss" => ShellExecResult {
                output: self.persona.ssh_vfs.netstat_output.clone(),
                delay_ms: 70,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "ip" => {
                let out = if args.first().copied() == Some("route")
                    || args.first().copied() == Some("r")
                {
                    self.persona.ssh_vfs.ip_route_output.clone()
                } else {
                    self.persona.ssh_vfs.ip_addr_output.clone()
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 50,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "ifconfig" => ShellExecResult {
                output: self.persona.ssh_vfs.ip_addr_output.clone(),
                delay_ms: 50,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "route" => ShellExecResult {
                output: self.persona.ssh_vfs.ip_route_output.clone(),
                delay_ms: 40,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "arp" => ShellExecResult {
                output: "Address                  HWtype  HWaddress           Flags Mask            Iface\n\
                         10.240.0.1               ether   00:1b:63:84:45:e6   C                     eth0\n\
                         10.240.0.10              ether   02:42:0a:f0:00:0a   C                     eth0"
                    .to_string(),
                delay_ms: 40,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "iptables" => ShellExecResult {
                output: self.persona.ssh_vfs.iptables_output.clone(),
                delay_ms: 60,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "ufw" => ShellExecResult {
                output: "Status: inactive".to_string(),
                delay_ms: 40,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "ping" => {
                let target = args
                    .iter()
                    .copied()
                    .find(|a| !a.starts_with('-'))
                    .unwrap_or("10.240.0.10");
                ShellExecResult {
                    output: format!(
                        "PING {target} ({target}) 56(84) bytes of data.\n\
                         64 bytes from {target}: icmp_seq=1 ttl=64 time=0.412 ms\n\
                         64 bytes from {target}: icmp_seq=2 ttl=64 time=0.389 ms\n\
                         --- {target} ping statistics ---\n\
                         2 packets transmitted, 2 received, 0% packet loss, time 1002ms"
                    ),
                    delay_ms: 800,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "dig" | "nslookup" | "host" => {
                let target = args.last().copied().unwrap_or("vault.internal.corp");
                ShellExecResult {
                    output: format!(
                        "Server:\t\t10.240.0.2\nAddress:\t10.240.0.2#53\n\nName:\t{target}\nAddress: 10.240.0.10"
                    ),
                    delay_ms: 120,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "uptime" => {
                let (_, h, m, s) = current_utc_hms();
                ShellExecResult {
                    output: format!(
                        " {h:02}:{m:02}:{s:02} up 41 days, 18:12,  1 user,  load average: 1.42, 1.38, 1.29"
                    ),
                    delay_ms: 30,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "date" => ShellExecResult {
                output: format_current_utc_date(),
                delay_ms: 20,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "nproc" => ShellExecResult {
                output: "64".to_string(),
                delay_ms: 15,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "arch" => ShellExecResult {
                output: "x86_64".to_string(),
                delay_ms: 15,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "ulimit" => ShellExecResult {
                output: if args.iter().any(|&a| a == "-n") {
                    "65536".to_string()
                } else {
                    "unlimited".to_string()
                },
                delay_ms: 15,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "umask" => ShellExecResult {
                output: "0022".to_string(),
                delay_ms: 15,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "sleep" => {
                let secs = args
                    .first()
                    .and_then(|s| s.trim_end_matches('s').parse::<f64>().ok())
                    .unwrap_or(1.0);
                let delay_ms = (secs * 1000.0).clamp(0.0, 5000.0) as u64;
                ShellExecResult {
                    output: String::new(),
                    delay_ms,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "time" => {
                if args.is_empty() {
                    ShellExecResult {
                        output: "\nreal\t0m0.000s\nuser\t0m0.000s\nsys\t0m0.000s".to_string(),
                        delay_ms: 5,
                        captured_indicators: Vec::new(),
                        should_exit: false,
                    }
                } else {
                    let inner = args.join(" ");
                    let mut res = self.execute_single(&inner, stdin_input, is_piped_out);
                    let secs = res.delay_ms / 1000;
                    let ms = res.delay_ms % 1000;
                    let timing = format!("real\t0m{secs}.{ms:03}s\nuser\t0m0.002s\nsys\t0m0.001s");
                    res.output = if res.output.is_empty() {
                        timing
                    } else {
                        format!("{}\n{timing}", res.output)
                    };
                    res
                }
            }
            "unset" | "alias" | "type" => ShellExecResult {
                output: String::new(),
                delay_ms: 15,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "passwd" | "chpasswd" => ShellExecResult {
                output: if prog == "chpasswd" {
                    "chpasswd: Permission denied.".to_string()
                } else {
                    "Changing password for user.\npasswd: Authentication token manipulation error"
                        .to_string()
                },
                delay_ms: 600,
                captured_indicators: vec![format!("credential_change_attempt:{cmd_line}")],
                should_exit: false,
            },
            "cut" => {
                let input = stdin_input.unwrap_or("");
                let mut delim = '\t';
                let mut field_1based: usize = 1;
                let mut i = 0;
                while i < args.len() {
                    if let Some(d) = args[i].strip_prefix("-d") {
                        if let Some(ch) = d.chars().next() {
                            delim = ch;
                        } else if let Some(next) = args.get(i + 1).and_then(|s| s.chars().next()) {
                            delim = next;
                            i += 1;
                        }
                    } else if let Some(f) = args[i].strip_prefix("-f") {
                        let f_str = if !f.is_empty() {
                            f
                        } else {
                            i += 1;
                            args.get(i).copied().unwrap_or("1")
                        };
                        if let Ok(n) = f_str.split(&[',', '-'][..]).next().unwrap_or("1").parse() {
                            field_1based = n;
                        }
                    }
                    i += 1;
                }
                let out: Vec<String> = input
                    .lines()
                    .map(|line| {
                        line.split(delim)
                            .nth(field_1based.saturating_sub(1))
                            .unwrap_or("")
                            .to_string()
                    })
                    .collect();
                ShellExecResult {
                    output: out.join("\n"),
                    delay_ms: 15,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "awk" => {
                let input = stdin_input.unwrap_or("");
                let expr = args.join(" ");
                let col: Option<usize> = expr
                    .find('$')
                    .and_then(|pos| {
                        let digits: String = expr[pos + 1..]
                            .chars()
                            .take_while(|c| c.is_ascii_digit())
                            .collect();
                        digits.parse::<usize>().ok()
                    });
                let out: Vec<String> = input
                    .lines()
                    .map(|line| match col {
                        Some(0) | None => line.to_string(),
                        Some(n) => line
                            .split_whitespace()
                            .nth(n.saturating_sub(1))
                            .unwrap_or("")
                            .to_string(),
                    })
                    .collect();
                ShellExecResult {
                    output: out.join("\n"),
                    delay_ms: 20,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "tr" | "sed" => ShellExecResult {
                output: stdin_input.unwrap_or("").to_string(),
                delay_ms: 15,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "nohup" => {
                if args.is_empty() {
                    ShellExecResult {
                        output: "nohup: missing operand".to_string(),
                        delay_ms: 20,
                        captured_indicators: Vec::new(),
                        should_exit: false,
                    }
                } else {
                    let inner = args.join(" ");
                    let mut res = self.execute_line(&inner);
                    res.captured_indicators.push(format!("nohup:{inner}"));
                    res
                }
            }
            "busybox" => {
                if args.is_empty() {
                    ShellExecResult {
                        output: "BusyBox v1.30.1 (Ubuntu 1:1.30.1-7ubuntu3) multi-call binary.\nCurrently defined functions:\n\t[, ash, awk, base64, cat, chmod, cp, cut, date, dd, df, echo, env, find, grep, head, id, kill, ln, ls, mkdir, mv, nc, ps, pwd, rm, sed, sh, sleep, sort, tail, tar, touch, tr, uname, uniq, uptime, wc, wget, which, whoami".to_string(),
                        delay_ms: 25,
                        captured_indicators: vec!["recon:busybox".to_string()],
                        should_exit: false,
                    }
                } else {
                    let inner = args.join(" ");
                    self.execute_line(&inner)
                }
            }
            "free" => {
                let out = if args.iter().any(|a| a.contains('h')) {
                    "               total        used        free      shared  buff/cache   available\n\
                     Mem:           504Gi       121Gi       297Gi       412Mi        84Gi       379Gi\n\
                     Swap:          8.0Gi          0B       8.0Gi"
                } else {
                    "               total        used        free      shared  buff/cache   available\n\
                     Mem:          516096      124210      305079         412       86806      388789\n\
                     Swap:           8191           0        8191"
                };
                ShellExecResult {
                    output: out.to_string(),
                    delay_ms: 30,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "df" => ShellExecResult {
                output: "Filesystem      Size  Used Avail Use% Mounted on\n\
                         udev            252G     0  252G   0% /dev\n\
                         tmpfs            51G  2.1M   51G   1% /run\n\
                         /dev/nvme0n1p2  1.8T  760G  1.1T  42% /\n\
                         /dev/nvme1n1p1  7.3T  4.1T  3.2T  57% /mnt/llm_checkpoints"
                    .to_string(),
                delay_ms: 40,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "du" => {
                let target = args
                    .iter()
                    .copied()
                    .find(|a| !a.starts_with('-'))
                    .unwrap_or(".");
                ShellExecResult {
                    output: format!("148M\t{target}"),
                    delay_ms: 60,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "env" | "printenv" => {
                let mut lines: Vec<String> = self
                    .env_vars
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect();
                lines.sort();
                ShellExecResult {
                    output: lines.join("\n"),
                    delay_ms: 30,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "export" => {
                for arg in args {
                    if let Some((k, v)) = arg.split_once('=') {
                        self.env_vars.insert(
                            k.to_string(),
                            v.trim_matches('"').trim_matches('\'').to_string(),
                        );
                    }
                }
                ShellExecResult {
                    output: String::new(),
                    delay_ms: 15,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "history" => {
                let out = self
                    .history
                    .iter()
                    .enumerate()
                    .map(|(i, cmd)| format!("{:5}  {}", i + 1, cmd))
                    .collect::<Vec<_>>()
                    .join("\n");
                ShellExecResult {
                    output: out,
                    delay_ms: 30,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "crontab" => {
                let out = if args.contains(&"-l") {
                    self.persona.ssh_vfs.crontab_output.clone()
                } else {
                    "crontab: no changes made to crontab".to_string()
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 45,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "sudo" => {
                if args.contains(&"-l") {
                    return ShellExecResult {
                        output: self.persona.ssh_vfs.sudo_l_output.clone(),
                        delay_ms: 120,
                        captured_indicators: Vec::new(),
                        should_exit: false,
                    };
                }
                if args.iter().any(|a| a.contains("sync_vault.py")) {
                    return ShellExecResult {
                        output: format!(
                            "[vault-sync] Authenticating to Vault cluster (10.240.0.10:8200)...\n\
                             [vault-sync] Loaded AWS key {} and PG database prod_core_ledger.\n\
                             [vault-sync] Completed key rotation heartbeat.",
                            self.persona
                                .postgres_data
                                .secrets_rows
                                .first()
                                .map(|r| r[1].as_str())
                                .unwrap_or("AKIA...")
                        ),
                        delay_ms: 900,
                        captured_indicators: Vec::new(),
                        should_exit: false,
                    };
                }
                if args.iter().any(|a| *a == "docker") {
                    return ShellExecResult {
                        output: self.persona.ssh_vfs.docker_ps_output.clone(),
                        delay_ms: 120,
                        captured_indicators: Vec::new(),
                        should_exit: false,
                    };
                }
                ShellExecResult {
                    output: format!(
                        "[sudo] password for {}: \nsudo: PAM authentication service temporarily busy (ldap://vault.internal.corp timeout after 2500ms)",
                        self.user
                    ),
                    delay_ms: 2000,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "su" => ShellExecResult {
                output: "Password: \nsu: Authentication failure".to_string(),
                delay_ms: 1800,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "docker" => {
                let sub = args.first().copied().unwrap_or("ps");
                let out = match sub {
                    "images" | "image" => self.persona.ssh_vfs.docker_images_output.clone(),
                    "network" => "NETWORK ID     NAME      DRIVER    SCOPE\n9a2b4c8d1e6f   bridge    bridge    local\n3f5a1c8e9d2b   host      host      local".to_string(),
                    _ => self.persona.ssh_vfs.docker_ps_output.clone(),
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 90,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "kubectl" => {
                let out = if args.contains(&"secrets") || args.contains(&"secret") {
                    self.persona.ssh_vfs.kubectl_secrets_output.clone()
                } else if args.contains(&"nodes") || args.contains(&"node") {
                    format!(
                        "NAME                 STATUS   ROLES           AGE   VERSION\n\
                         {:<20} Ready    control-plane   41d   v1.28.4",
                        self.persona.hostname
                    )
                } else {
                    self.persona.ssh_vfs.kubectl_pods_output.clone()
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 150,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "aws" => {
                let out = if args.contains(&"s3") {
                    format!(
                        "2026-10-12 04:12:09 {}-db-backups-private\n\
                         2026-10-19 11:20:44 {}-checkpoints",
                        self.persona.hostname, self.persona.hostname
                    )
                } else {
                    format!(
                        "{{\n    \"UserId\": \"AIDA9ESWWIPK5S7M0RAP\",\n    \"Account\": \"492810491820\",\n    \"Arn\": \"arn:aws:iam::492810491820:user/{}\"\n}}",
                        self.persona.ssh_vfs.default_user
                    )
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 250,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "redis-cli" => {
                let joined_upper = args.join(" ").to_ascii_uppercase();
                let out = if joined_upper.contains("KEYS") {
                    let mut keys: Vec<&str> = self
                        .persona
                        .redis_data
                        .kv_store
                        .keys()
                        .map(|s| s.as_str())
                        .collect();
                    keys.sort();
                    keys.iter()
                        .enumerate()
                        .map(|(i, k)| format!("{}) \"{}\"", i + 1, k))
                        .collect::<Vec<_>>()
                        .join("\n")
                } else if let Some(pos) = args.iter().position(|a| a.eq_ignore_ascii_case("GET")) {
                    let key = args.get(pos + 1).copied().unwrap_or("");
                    self.persona
                        .redis_data
                        .kv_store
                        .get(key)
                        .map(|v| format!("\"{v}\""))
                        .unwrap_or_else(|| "(nil)".to_string())
                } else {
                    format!(
                        "# Server\nredis_version:{}\nrole:master\ndb0:keys={},expires=2",
                        self.persona.redis_data.redis_version,
                        self.persona.redis_data.kv_store.len()
                    )
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 90,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "psql" => {
                let pg = &self.persona.postgres_data;
                let joined_upper = args.join(" ").to_ascii_uppercase();
                let out = if joined_upper.contains("VAULT_SECRETS") {
                    let mut lines = vec![
                        "     key_name      |                   secret_value                    |               canary_verify_url".to_string(),
                        "-------------------+---------------------------------------------------+-----------------------------------------------".to_string(),
                    ];
                    for r in &pg.secrets_rows {
                        lines.push(format!(" {:<17} | {:<49} | {}", r[0], r[1], r[2]));
                    }
                    lines.push(format!("({} rows)", pg.secrets_rows.len()));
                    lines.join("\n")
                } else {
                    let mut lines = vec![
                        " id |      username      |                        password_hash                         |      role".to_string(),
                        "----+--------------------+--------------------------------------------------------------+----------------".to_string(),
                    ];
                    for r in &pg.users_rows {
                        lines.push(format!(
                            " {:<2} | {:<18} | {:<60} | {}",
                            r[0], r[1], r[2], r[3]
                        ));
                    }
                    lines.push(format!("({} rows)", pg.users_rows.len()));
                    lines.join("\n")
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 140,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "git" => {
                let out = if args.contains(&"remote") {
                    format!(
                        "origin\thttps://git.internal.corp/{}/monorepo.git (fetch)\norigin\thttps://git.internal.corp/{}/monorepo.git (push)",
                        self.persona.hostname, self.persona.hostname
                    )
                } else {
                    "On branch release/prod-hotfix\nnothing to commit, working tree clean"
                        .to_string()
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 45,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "python3" | "python" => {
                if args.contains(&"--version") || args.contains(&"-V") {
                    return ShellExecResult {
                        output: "Python 3.10.12".to_string(),
                        delay_ms: 30,
                        captured_indicators: Vec::new(),
                        should_exit: false,
                    };
                }
                if args.iter().any(|a| a.contains("sync_vault.py")) {
                    return ShellExecResult {
                        output: format!(
                            "Syncing vault secrets for {} to {}...",
                            self.persona.hostname,
                            self.persona
                                .postgres_data
                                .secrets_rows
                                .first()
                                .map(|r| r[2].as_str())
                                .unwrap_or("https://canary.internal")
                        ),
                        delay_ms: 300,
                        captured_indicators: Vec::new(),
                        should_exit: false,
                    };
                }
                let indicators = extract_urls_and_ips(cmd_line);
                ShellExecResult {
                    output: String::new(),
                    delay_ms: 150,
                    captured_indicators: indicators,
                    should_exit: false,
                }
            }
            "which" | "whereis" => {
                let target = args.first().copied().unwrap_or("bash");
                ShellExecResult {
                    output: format!("/usr/bin/{target}"),
                    delay_ms: 20,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "find" => {
                let start = args
                    .first()
                    .copied()
                    .filter(|a| !a.starts_with('-'))
                    .unwrap_or(&self.cwd);
                let resolved = self.resolve_path(start);
                let mut paths: Vec<String> = self
                    .persona
                    .ssh_vfs
                    .files
                    .keys()
                    .chain(self.cow_files.keys())
                    .filter(|k| k.starts_with(&resolved) || resolved == "/")
                    .cloned()
                    .collect();
                paths.sort();
                paths.dedup();
                ShellExecResult {
                    output: paths.join("\n"),
                    delay_ms: 90,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "file" => {
                let target = args.last().copied().unwrap_or("deploy_notes.txt");
                ShellExecResult {
                    output: format!("{target}: ASCII text"),
                    delay_ms: 30,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "stat" => {
                let target = args.last().copied().unwrap_or(".");
                ShellExecResult {
                    output: format!(
                        "  File: {target}\n  Size: 4096      \tBlocks: 8          IO Block: 4096   regular file\nAccess: (0640/-rw-r-----)  Uid: ( 1000/{user})   Gid: ( 1000/{user})",
                        user = self.user
                    ),
                    delay_ms: 30,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "cd" => {
                let target = args.first().copied().unwrap_or("~");
                let resolved = self.resolve_path(target);
                self.cwd = resolved.clone();
                self.env_vars.insert("PWD".to_string(), resolved);
                ShellExecResult {
                    output: String::new(),
                    delay_ms: 15,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "ls" | "dir" | "ll" => {
                let show_long =
                    prog == "ll" || args.iter().any(|a| a.starts_with('-') && a.contains('l'));
                let show_all =
                    prog == "ll" || args.iter().any(|a| a.starts_with('-') && a.contains('a'));
                let one_per_line =
                    is_piped_out || args.iter().any(|a| a.starts_with('-') && a.contains('1'));
                let target_arg = args
                    .iter()
                    .copied()
                    .find(|a| !a.starts_with('-'))
                    .unwrap_or(&self.cwd);
                let resolved = self.resolve_path(target_arg);

                let mut entries = self
                    .persona
                    .ssh_vfs
                    .directories
                    .get(&resolved)
                    .cloned()
                    .unwrap_or_default();

                let prefix = if resolved == "/" {
                    "/".to_string()
                } else {
                    format!("{resolved}/")
                };
                for cow_path in self.cow_files.keys() {
                    if let Some(rel) = cow_path.strip_prefix(&prefix) {
                        if !rel.contains('/') && !entries.contains(&rel.to_string()) {
                            entries.push(rel.to_string());
                        }
                    }
                }

                if !show_all {
                    entries.retain(|e| !e.starts_with('.'));
                }
                entries.sort();

                let is_home_dir = resolved.starts_with("/home/") || resolved == "/home";
                let output = if show_long {
                    let mut lines = vec![format!("total {}", (entries.len() + 2) * 4)];
                    let dot_owner = if is_home_dir { self.user.as_str() } else { "root" };
                    if show_all {
                        lines.push(format!(
                            "drwxr-xr-x 5 {dot_owner:<4} {dot_owner:<4}  4096 Nov 22 03:12 ."
                        ));
                        lines.push("drwxr-xr-x 4 root root  4096 Oct 12 09:00 ..".to_string());
                    }
                    for entry in entries {
                        let full = if resolved == "/" {
                            format!("/{entry}")
                        } else {
                            format!("{resolved}/{entry}")
                        };
                        let is_dir = self.persona.ssh_vfs.directories.contains_key(&full);
                        let perms = if full == "/tmp" {
                            "drwxrwxrwt"
                        } else if is_dir {
                            "drwxr-xr-x"
                        } else {
                            "-rw-r--r--"
                        };
                        let owner = if full.starts_with("/home/") && full != "/home" {
                            self.user.as_str()
                        } else {
                            "root"
                        };
                        let size = self
                            .read_vfs_file(&full)
                            .map(|c| c.len())
                            .unwrap_or(4096);
                        let ts = deterministic_entry_timestamp(&entry);
                        lines.push(format!(
                            "{perms} 1 {owner:<4} {owner:<4} {size:>5} {ts} {entry}"
                        ));
                    }
                    lines.join("\n")
                } else if one_per_line {
                    entries.join("\n")
                } else {
                    entries.join("  ")
                };
                ShellExecResult {
                    output,
                    delay_ms: 35,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "cat" | "tac" | "nl" | "less" | "more" => {
                let file_args: Vec<&str> =
                    args.iter().copied().filter(|a| !a.starts_with('-')).collect();
                if file_args.is_empty() {
                    return ShellExecResult {
                        output: stdin_input.unwrap_or("").to_string(),
                        delay_ms: 15,
                        captured_indicators: Vec::new(),
                        should_exit: false,
                    };
                }
                let mut outputs = Vec::new();
                for target in file_args {
                    let resolved = self.resolve_path(target);
                    if resolved == "/etc/shadow" && self.user != "root" {
                        self.last_exit_code = 1;
                        outputs.push("cat: /etc/shadow: Permission denied".to_string());
                        continue;
                    }
                    match self.read_vfs_file(&resolved) {
                        Some(content) => {
                            if prog == "tac" {
                                let rev: Vec<&str> = content.lines().rev().collect();
                                outputs.push(rev.join("\n"));
                            } else if prog == "nl" {
                                let numbered: Vec<String> = content
                                    .lines()
                                    .enumerate()
                                    .map(|(i, l)| format!("{:6}\t{}", i + 1, l))
                                    .collect();
                                outputs.push(numbered.join("\n"));
                            } else {
                                outputs.push(content);
                            }
                        }
                        None => {
                            self.last_exit_code = 1;
                            outputs.push(format!("{prog}: {target}: No such file or directory"));
                        }
                    }
                }
                ShellExecResult {
                    output: outputs.join("\n"),
                    delay_ms: 40,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            // Pipeline & Text Filter Commands
            "grep" | "egrep" | "fgrep" => {
                let case_insensitive =
                    args.iter().any(|a| a.starts_with('-') && a.contains('i'));
                let invert = args.iter().any(|a| a.starts_with('-') && a.contains('v'));
                let non_flags: Vec<&str> =
                    args.iter().copied().filter(|a| !a.starts_with('-')).collect();
                let pattern = non_flags
                    .first()
                    .copied()
                    .unwrap_or("")
                    .trim_matches('"')
                    .trim_matches('\'');
                let source_text = if let Some(file_arg) = non_flags.get(1) {
                    let resolved = self.resolve_path(file_arg);
                    self.read_vfs_file(&resolved).unwrap_or_default()
                } else {
                    stdin_input.unwrap_or("").to_string()
                };
                let pat_cmp = if case_insensitive {
                    pattern.to_ascii_lowercase()
                } else {
                    pattern.to_string()
                };
                let matched: Vec<&str> = source_text
                    .lines()
                    .filter(|line| {
                        let hay = if case_insensitive {
                            line.to_ascii_lowercase()
                        } else {
                            (*line).to_string()
                        };
                        let hit = hay.contains(&pat_cmp);
                        if invert { !hit } else { hit }
                    })
                    .collect();
                ShellExecResult {
                    output: matched.join("\n"),
                    delay_ms: 25,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "head" | "tail" => {
                let mut count = 10usize;
                for (i, &arg) in args.iter().enumerate() {
                    if arg == "-n" {
                        if let Some(n_str) = args.get(i + 1) {
                            count = n_str.parse().unwrap_or(10);
                        }
                    } else if let Some(n_str) = arg.strip_prefix("-n") {
                        count = n_str.parse().unwrap_or(10);
                    }
                }
                let file_arg = args
                    .iter()
                    .copied()
                    .find(|a| !a.starts_with('-') && a.parse::<usize>().is_err());
                let source_text = match file_arg {
                    Some(f) => {
                        let resolved = self.resolve_path(f);
                        self.read_vfs_file(&resolved).unwrap_or_default()
                    }
                    None => stdin_input.unwrap_or("").to_string(),
                };
                let lines: Vec<&str> = source_text.lines().collect();
                let selected: Vec<&str> = if prog == "head" {
                    lines.into_iter().take(count).collect()
                } else {
                    let skip = lines.len().saturating_sub(count);
                    lines.into_iter().skip(skip).collect()
                };
                ShellExecResult {
                    output: selected.join("\n"),
                    delay_ms: 20,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "wc" => {
                let text = stdin_input.unwrap_or("");
                let lines = text.lines().count();
                let words = text.split_whitespace().count();
                let bytes = text.len();
                let out = if args.contains(&"-l") {
                    lines.to_string()
                } else if args.contains(&"-c") {
                    bytes.to_string()
                } else {
                    format!("{lines:7} {words:7} {bytes:7}")
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 15,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "sort" => {
                let mut lines: Vec<&str> = stdin_input.unwrap_or("").lines().collect();
                lines.sort();
                if args.contains(&"-r") {
                    lines.reverse();
                }
                ShellExecResult {
                    output: lines.join("\n"),
                    delay_ms: 20,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "uniq" => {
                let mut lines: Vec<&str> = stdin_input.unwrap_or("").lines().collect();
                lines.dedup();
                ShellExecResult {
                    output: lines.join("\n"),
                    delay_ms: 20,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "base64" => {
                let decode = args.contains(&"-d") || args.contains(&"--decode");
                let text = stdin_input.unwrap_or("").trim();
                let out = if decode {
                    base64::engine::general_purpose::STANDARD
                        .decode(text)
                        .map(|b| String::from_utf8_lossy(&b).into_owned())
                        .unwrap_or_else(|_| "base64: invalid input".to_string())
                } else {
                    base64::engine::general_purpose::STANDARD.encode(text.as_bytes())
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 20,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "sha256sum" | "md5sum" => {
                let text = stdin_input.unwrap_or("");
                let mut hasher = Sha256::new();
                hasher.update(text.as_bytes());
                let digest = hasher.finalize();
                let hex_str: String = digest.iter().map(|b| format!("{b:02x}")).collect();
                let out = if prog == "md5sum" {
                    format!("{}  -", &hex_str[..32])
                } else {
                    format!("{hex_str}  -")
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 25,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "touch" => {
                for &f in args.iter().filter(|a| !a.starts_with('-')) {
                    let resolved = self.resolve_path(f);
                    if self.read_vfs_file(&resolved).is_none() {
                        self.write_cow_file(&resolved, "", false);
                    }
                }
                ShellExecResult {
                    output: String::new(),
                    delay_ms: 20,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "rm" => {
                for &f in args.iter().filter(|a| !a.starts_with('-')) {
                    let resolved = self.resolve_path(f);
                    self.cow_files.remove(&resolved);
                }
                ShellExecResult {
                    output: String::new(),
                    delay_ms: 25,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "chmod" | "chown" | "mkdir" | "mv" | "cp" | "ln" | "tar" | "gzip" | "unzip"
            | "kill" | "pkill" | "killall" => ShellExecResult {
                output: String::new(),
                delay_ms: 35,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "wget" | "curl" | "tftp" | "scp" | "sftp" | "fetch" | "nc" | "netcat" | "ncat"
            | "socat" => {
                let indicators = extract_urls_and_ips(cmd_line);
                let target_url = indicators
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "http://127.0.0.1/index.html".to_string());

                let mut saved_name = target_url
                    .rsplit('/')
                    .next()
                    .filter(|s| !s.is_empty())
                    .unwrap_or("index.html")
                    .to_string();

                if let Some(out_pos) = args.iter().position(|&a| a == "-O" || a == "-o") {
                    if let Some(&out_file) = args.get(out_pos + 1) {
                        saved_name = out_file.to_string();
                        if out_file != "-" {
                            let resolved = self.resolve_path(out_file);
                            self.write_cow_file(&resolved, "#!/bin/sh\n", false);
                        }
                    }
                }

                let is_silent = args.iter().any(|&a| {
                    a == "-q" || a == "-s" || a == "-fsSL" || a == "-sL" || a == "-sS" || a == "-O-"
                });
                let output = if is_silent {
                    String::new()
                } else if prog == "wget" {
                    let (ts, _, _, _) = current_utc_hms();
                    format!(
                        "--{ts}--  {target_url}\n\
                         Connecting... connected.\n\
                         HTTP request sent, awaiting response... 200 OK\n\
                         Length: 184320 (180K) [application/octet-stream]\n\
                         Saving to: '{saved_name}'\n\
                         \n\
                         {saved_name} 100%[===================>] 180.00K   412KB/s    in 0.4s\n\
                         \n\
                         {ts} (412 KB/s) - '{saved_name}' saved [184320/184320]"
                    )
                } else {
                    String::new()
                };

                ShellExecResult {
                    output,
                    delay_ms: 900,
                    captured_indicators: if indicators.is_empty() {
                        vec![cmd_line.to_string()]
                    } else {
                        indicators
                    },
                    should_exit: false,
                }
            }
            "echo" | "printf" => {
                let raw = args.join(" ");
                let trimmed = raw.trim_matches('"').trim_matches('\'');
                let expanded = trimmed
                    .replace("$?", &self.last_exit_code.to_string())
                    .replace("$USER", &self.user)
                    .replace("$HOSTNAME", &self.persona.hostname)
                    .replace(
                        "$HOME",
                        self.env_vars
                            .get("HOME")
                            .map(|s| s.as_str())
                            .unwrap_or("/root"),
                    );
                ShellExecResult {
                    output: expanded,
                    delay_ms: 15,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "sh" | "bash" => {
                if let Some(c_pos) = args.iter().position(|&a| a == "-c") {
                    let inner = args[c_pos + 1..]
                        .join(" ")
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_string();
                    if !inner.is_empty() && !inner.starts_with("sh ") && !inner.starts_with("bash ")
                    {
                        return self.execute_line(&inner);
                    }
                }
                let indicators = extract_urls_and_ips(cmd_line);
                ShellExecResult {
                    output: String::new(),
                    delay_ms: 80,
                    captured_indicators: indicators,
                    should_exit: false,
                }
            }
            _ => {
                if prog.starts_with("./")
                    || prog.starts_with("/tmp/")
                    || prog.starts_with("/var/tmp/")
                {
                    let indicators = extract_urls_and_ips(cmd_line);
                    return ShellExecResult {
                        output: format!(
                            "{prog}: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.38' not found (required by {prog})"
                        ),
                        delay_ms: 600,
                        captured_indicators: if indicators.is_empty() {
                            vec![format!("exec_payload:{cmd_line}")]
                        } else {
                            indicators
                        },
                        should_exit: false,
                    };
                }

                self.last_exit_code = 127;
                ShellExecResult {
                    output: format!("bash: {prog}: command not found"),
                    delay_ms: 40,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
        }
    }

    pub fn resolve_path(&self, raw: &str) -> String {
        let home = if self.user == "root" {
            "/root".to_string()
        } else {
            format!("/home/{}", self.persona.ssh_vfs.default_user)
        };
        let expanded = if raw == "~" {
            home
        } else if let Some(stripped) = raw.strip_prefix("~/") {
            format!("{home}/{stripped}")
        } else if raw.starts_with('/') {
            raw.to_string()
        } else if self.cwd == "/" {
            format!("/{raw}")
        } else {
            format!("{}/{}", self.cwd.trim_end_matches('/'), raw)
        };

        // Normalize `.` and `..` path components
        let mut stack = Vec::new();
        for comp in expanded.split('/') {
            match comp {
                "" | "." => {}
                ".." => {
                    stack.pop();
                }
                other => stack.push(other),
            }
        }
        if stack.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", stack.join("/"))
        }
    }
}

fn split_chained_commands(line: &str) -> Vec<&str> {
    let mut result = Vec::new();
    for segment in line.split(';') {
        for sub in segment.split("&&") {
            result.push(sub);
        }
    }
    result
}

fn parse_redirection(cmd: &str) -> (&str, Option<(&str, bool)>) {
    if let Some((left, right)) = cmd.split_once(">>") {
        let target = right
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches('"')
            .trim_matches('\'');
        if !target.is_empty() {
            return (left.trim(), Some((target, true)));
        }
    }
    if let Some((left, right)) = cmd.split_once('>') {
        let target = right
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches('"')
            .trim_matches('\'');
        if !target.is_empty() {
            return (left.trim(), Some((target, false)));
        }
    }
    (cmd, None)
}

fn extract_urls_and_ips(cmd_line: &str) -> Vec<String> {
    let mut found = Vec::new();
    for token in cmd_line.split_whitespace() {
        let cleaned = token.trim_matches(|c| c == '"' || c == '\'' || c == ';');
        if cleaned.starts_with("http://")
            || cleaned.starts_with("https://")
            || cleaned.starts_with("ftp://")
            || cleaned.starts_with("tftp://")
            || cleaned.contains("/dev/tcp/")
        {
            found.push(cleaned.to_string());
        }
    }
    found
}

fn current_utc_hms() -> (String, u64, u64, u64) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (year, month, day, _wday) = civil_from_days((secs / 86400) as i64);
    let rem = secs % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    (
        format!("{year:04}-{month:02}-{day:02} {h:02}:{m:02}:{s:02}"),
        h,
        m,
        s,
    )
}

fn format_current_utc_date() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86400) as i64;
    let (year, month, day, wday) = civil_from_days(days);
    let rem = secs % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    const WDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let w = WDAYS[(wday.rem_euclid(7)) as usize];
    let mon = MONTHS[(month.saturating_sub(1) as usize).min(11)];
    format!("{w} {mon} {day:02} {h:02}:{m:02}:{s:02} UTC {year:04}")
}

fn civil_from_days(z: i64) -> (i64, u32, u32, i64) {
    let wday = z;
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m, d, wday)
}

fn deterministic_entry_timestamp(name: &str) -> String {
    let mut h = 0x811c_9dc5u32;
    for &b in name.as_bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    const MONTHS: [&str; 3] = ["Sep", "Oct", "Nov"];
    let mon = MONTHS[(h as usize) % MONTHS.len()];
    let day = 1 + ((h >> 8) % 21);
    let hour = (h >> 16) % 24;
    let min = (h >> 24) % 60;
    format!("{mon} {day:2} {hour:02}:{min:02}")
}
