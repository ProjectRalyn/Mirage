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
    cow_dirs: std::collections::HashSet<String>,
    cow_total_bytes: usize,
    virtual_clock_offset_ns: u64,
    rng_state: u64,
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
            format!("/home/{user}")
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
        env_vars.insert("PWD".to_string(), home.clone());
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

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15)
            ^ persona.epoch_id
            ^ 0xBF58_476D_1CE4_E5B9;

        Self {
            persona,
            user,
            cwd: home,
            client_ip: "10.240.0.5".to_string(),
            os_is_arch: false,
            last_exit_code: 0,
            env_vars,
            cow_files: HashMap::new(),
            cow_dirs: std::collections::HashSet::new(),
            cow_total_bytes: 0,
            virtual_clock_offset_ns: 0,
            rng_state: if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed },
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
            format!("/home/{}", self.user)
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

    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    pub fn last_exit_code(&self) -> i32 {
        self.last_exit_code
    }

    pub fn history(&self) -> &[String] {
        &self.history
    }

    fn map_to_persona_path(&self, resolved: &str) -> String {
        if self.user == "root" || self.user == self.persona.ssh_vfs.default_user {
            return resolved.to_string();
        }
        let user_home = format!("/home/{}", self.user);
        let default_home = format!("/home/{}", self.persona.ssh_vfs.default_user);
        if resolved == user_home {
            default_home
        } else if let Some(rest) = resolved.strip_prefix(&format!("{user_home}/")) {
            format!("{default_home}/{rest}")
        } else {
            resolved.to_string()
        }
    }

    fn current_virtual_now_ns(&self) -> u64 {
        let wall_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        wall_ns.saturating_add(self.virtual_clock_offset_ns)
    }

    fn current_loadavg(&self) -> (f32, f32, f32) {
        let secs = self.current_virtual_now_ns() / 1_000_000_000;
        let bucket = (secs / 3) % 19;
        let jitter1 = (bucket as f32 - 9.0) * 0.03;
        let jitter5 = ((bucket % 7) as f32 - 3.0) * 0.01;
        let l1 = (1.42 + jitter1).clamp(0.85, 2.40);
        let l5 = (1.38 + jitter5).clamp(0.95, 2.10);
        let l15 = 1.29;
        (l1, l5, l15)
    }

    fn next_random_u16(&mut self) -> u16 {
        let mut x = self.rng_state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng_state = if x == 0 { 0x9E37_79B9_7F4A_7C15 } else { x };
        (self.rng_state % 32768) as u16
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

    /// Execute a full command line (supports `;`, `&&`, pipes `|`, command substitution `$(...)`,
    /// arithmetic `$((...))`, env expansion `$VAR`, and `>` / `>>` redirection).
    pub fn execute_line(&mut self, raw_line: &str) -> ShellExecResult {
        self.execute_line_with_depth(raw_line, 0)
    }

    fn execute_line_with_depth(&mut self, raw_line: &str, depth: u8) -> ShellExecResult {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            return ShellExecResult {
                output: String::new(),
                delay_ms: 0,
                captured_indicators: Vec::new(),
                should_exit: false,
            };
        }

        if depth == 0 {
            self.history.push(line.to_string());
        }

        let mut combined_output = Vec::new();
        let mut total_delay_ms = 0u64;
        let mut captured_indicators = Vec::new();
        let mut should_exit = false;

        for (subcmd, requires_prev_zero) in split_chained_commands(line) {
            let subcmd = subcmd.trim();
            if subcmd.is_empty() {
                continue;
            }
            if requires_prev_zero && self.last_exit_code != 0 {
                continue;
            }
            let res = self.execute_pipeline_and_redirection(subcmd, depth);
            self.virtual_clock_offset_ns = self
                .virtual_clock_offset_ns
                .saturating_add(res.delay_ms.saturating_mul(1_000_000));
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
        if depth == 0 && !final_output.is_empty() && !final_output.ends_with('\n') {
            final_output.push('\n');
        }

        ShellExecResult {
            output: final_output,
            delay_ms: total_delay_ms.min(8000),
            captured_indicators,
            should_exit,
        }
    }

    fn execute_pipeline_and_redirection(&mut self, cmd_line: &str, depth: u8) -> ShellExecResult {
        // Strip trailing `2>&1` or `2>/dev/null`
        let cleaned = cmd_line
            .replace("2>&1", "")
            .replace("2>/dev/null", "")
            .replace("&>/dev/null", "");
        let cleaned = cleaned.trim();

        // Check for output redirection `>>` or `>`
        let (pipeline_part, redirect_target) = parse_redirection(cleaned);

        // Split pipeline by `|` (top-level only)
        let stages = split_top_level_pipes(pipeline_part);
        if stages.is_empty() {
            return ShellExecResult {
                output: String::new(),
                delay_ms: 0,
                captured_indicators: Vec::new(),
                should_exit: false,
            };
        }

        let (expanded_first, sub_delay0, mut sub_ind0) =
            self.expand_variables(stages[0], depth);
        let mut res = self.execute_single(&expanded_first, None, stages.len() > 1);
        res.delay_ms = res.delay_ms.saturating_add(sub_delay0);
        sub_ind0.extend(res.captured_indicators);
        res.captured_indicators = sub_ind0;

        for (idx, &stage) in stages[1..].iter().enumerate() {
            let (expanded_stage, sub_delay, sub_ind) = self.expand_variables(stage, depth);
            let has_more_pipes = idx + 2 < stages.len();
            let next_res = self.execute_single(&expanded_stage, Some(&res.output), has_more_pipes);
            res.output = next_res.output;
            res.delay_ms = res
                .delay_ms
                .saturating_add(sub_delay)
                .saturating_add(next_res.delay_ms);
            res.captured_indicators.extend(sub_ind);
            res.captured_indicators.extend(next_res.captured_indicators);
            if next_res.should_exit {
                res.should_exit = true;
                break;
            }
        }

        if let Some((target_file, is_append)) = redirect_target {
            let (expanded_target, _, _) = self.expand_variables(target_file, depth);
            let resolved = self.resolve_path(expanded_target.trim());
            if resolved != "/dev/null" {
                self.write_cow_file(&resolved, &res.output, is_append);
                res.captured_indicators
                    .push(format!("file_write:{resolved} ({} bytes)", res.output.len()));
            }
            res.output.clear();
        }

        res
    }

    fn expand_variables(&mut self, input: &str, depth: u8) -> (String, u64, Vec<String>) {
        if !input.contains('$') && !input.contains('`') {
            return (input.to_string(), 0, Vec::new());
        }
        let mut out = input.to_string();
        let mut extra_delay_ms = 0u64;
        let mut indicators = Vec::new();

        // 1. Expand command substitutions `$(...)` (when not `$((...))`) and backticks `` `...` ``
        if depth < 2 {
            for _ in 0..4 {
                if let Some((start, end, inner)) = find_command_substitution(&out) {
                    let sub_res = self.execute_line_with_depth(&inner, depth + 1);
                    extra_delay_ms = extra_delay_ms.saturating_add(sub_res.delay_ms);
                    indicators.extend(sub_res.captured_indicators);
                    let replacement = sub_res.output.trim_end_matches('\n').replace('\n', " ");
                    out.replace_range(start..end, &replacement);
                } else {
                    break;
                }
            }
        }

        // 2. Expand arithmetic expressions `$(( ... ))`
        for _ in 0..4 {
            if let Some((start, end, expr)) = find_arithmetic_expansion(&out) {
                let val = eval_arith_expr(&expr, &self.env_vars);
                out.replace_range(start..end, &val.to_string());
            } else {
                break;
            }
        }

        // 3. Expand `$RANDOM` and `${RANDOM}` (each occurrence draws a fresh value)
        while let Some(pos) = out.find("${RANDOM}") {
            let r = self.next_random_u16().to_string();
            out.replace_range(pos..pos + 9, &r);
        }
        while let Some(pos) = out.find("$RANDOM") {
            let r = self.next_random_u16().to_string();
            out.replace_range(pos..pos + 7, &r);
        }

        // 4. Expand special shell variables & environment map
        out = out.replace("$?", &self.last_exit_code.to_string());
        out = out.replace("${?}", &self.last_exit_code.to_string());
        let uid_str = if self.user == "root" { "0" } else { "1000" };
        out = out.replace("${UID}", uid_str);
        out = out.replace("$UID", uid_str);
        out = out.replace("${EUID}", uid_str);
        out = out.replace("$EUID", uid_str);
        out = out.replace("$PWD", &self.cwd);
        out = out.replace("${PWD}", &self.cwd);

        // Sort keys by descending length so `$HOME_DIR` isn't partially corrupted by `$HOME`
        let mut keys: Vec<&String> = self.env_vars.keys().collect();
        keys.sort_by(|a, b| b.len().cmp(&a.len()));
        for k in keys {
            if let Some(v) = self.env_vars.get(k) {
                out = out.replace(&format!("${{{k}}}"), v);
                out = out.replace(&format!("${k}"), v);
            }
        }

        (out, extra_delay_ms, indicators)
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
            let secs = (self.current_virtual_now_ns() / 1_000_000_000) % 86400;
            let up = 3_591_248 + secs;
            let idle = 14_310_291 + secs * 4;
            return Some(format!("{up}.42 {idle}.18\n"));
        }
        if resolved_path == "/proc/loadavg" {
            let (l1, l5, l15) = self.current_loadavg();
            return Some(format!("{l1:.2} {l5:.2} {l15:.2} 2/418 19402\n"));
        }
        if resolved_path == "/proc/1/comm" {
            return Some("systemd\n".to_string());
        }
        if resolved_path == "/proc/1/cmdline" || resolved_path == "/proc/self/cmdline" {
            return Some("/sbin/init\n".to_string());
        }
        if resolved_path == "/proc/1/status" || resolved_path == "/proc/self/status" {
            return Some("Name:\tsystemd\nUmask:\t0000\nState:\tS (sleeping)\nTgid:\t1\nPid:\t1\nPPid:\t0\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n".to_string());
        }

        let lookup_path = self.map_to_persona_path(resolved_path);
        let raw = self.persona.ssh_vfs.files.get(&lookup_path)?.clone();
        if self.user != "root"
            && self.user != self.persona.ssh_vfs.default_user
            && matches!(
                resolved_path,
                "/etc/passwd" | "/etc/group" | "/etc/shadow" | "/etc/sudoers"
            )
        {
            return Some(raw.replace(&self.persona.ssh_vfs.default_user, &self.user));
        }
        Some(raw)
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

        // Check bare `VAR=val` assignment (supports multi-word values after expansion)
        if !prog.starts_with('/') && prog.contains('=') {
            if let Some((k, _)) = prog.split_once('=') {
                if is_valid_var_name(k) {
                    if let Some((_, full_val)) = cmd_line.trim().split_once('=') {
                        self.env_vars.insert(
                            k.to_string(),
                            full_val.trim().trim_matches('"').trim_matches('\'').to_string(),
                        );
                        self.last_exit_code = 0;
                        return ShellExecResult {
                            output: String::new(),
                            delay_ms: 5,
                            captured_indicators: Vec::new(),
                            should_exit: false,
                        };
                    }
                }
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
                let (l1, l5, l15) = self.current_loadavg();
                ShellExecResult {
                    output: format!(
                        " {h:02}:{m:02}:00 up 41 days, 18:12,  1 user,  load average: {l1:.2}, {l5:.2}, {l15:.2}\n\
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
            "ps" => {
                let mut out = self
                    .persona
                    .ssh_vfs
                    .ps_aux_output
                    .replace(&self.persona.ssh_vfs.default_user, &self.user);
                if self.os_is_arch {
                    out = out.replace(
                        "/usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main",
                        "/usr/bin/postgres -D /var/lib/postgres/data",
                    );
                    out = out
                        .lines()
                        .filter(|line| !line.contains("php-fpm"))
                        .collect::<Vec<_>>()
                        .join("\n");
                }
                ShellExecResult {
                    output: out,
                    delay_ms: 80,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "top" | "htop" => {
                let out = self
                    .persona
                    .ssh_vfs
                    .top_output
                    .replace(&self.persona.ssh_vfs.default_user, &self.user);
                ShellExecResult {
                    output: out,
                    delay_ms: 150,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
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
                let (l1, l5, l15) = self.current_loadavg();
                ShellExecResult {
                    output: format!(
                        " {h:02}:{m:02}:{s:02} up 41 days, 18:12,  1 user,  load average: {l1:.2}, {l5:.2}, {l15:.2}"
                    ),
                    delay_ms: 30,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "date" => {
                let now_ns = self.current_virtual_now_ns();
                let fmt_arg = args.iter().copied().find(|a| a.starts_with('+'));
                let output = match fmt_arg {
                    Some(fmt) => format_date_with_spec(&fmt[1..], now_ns),
                    None => format_utc_date_from_ns(now_ns),
                };
                ShellExecResult {
                    output,
                    delay_ms: 15,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
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
                let mapped_resolved = self.map_to_persona_path(&resolved);

                let prefix = if resolved == "/" {
                    "/".to_string()
                } else {
                    format!("{resolved}/")
                };

                let is_known_dir = self
                    .persona
                    .ssh_vfs
                    .directories
                    .contains_key(&mapped_resolved)
                    || self.cow_dirs.contains(&resolved)
                    || self.cow_files.keys().any(|k| k.starts_with(&prefix))
                    || self.cow_dirs.iter().any(|d| d.starts_with(&prefix));

                if !is_known_dir {
                    // Check if target is a single file (CoW or VFS)
                    if let Some(content) = self.read_vfs_file(&resolved) {
                        let is_proc_file = resolved.starts_with("/proc/");
                        let perms = if is_proc_file {
                            "-r--r--r--"
                        } else {
                            "-rw-r--r--"
                        };
                        let owner = if resolved.starts_with("/home/") && resolved != "/home" {
                            self.user.as_str()
                        } else if self.cow_files.contains_key(&resolved) {
                            self.user.as_str()
                        } else {
                            "root"
                        };
                        let size = if is_proc_file { 0 } else { content.len() };
                        let ts = deterministic_entry_timestamp(target_arg);
                        let output = if show_long {
                            format!("{perms} 1 {owner:<4} {owner:<4} {size:>5} {ts} {target_arg}")
                        } else {
                            target_arg.to_string()
                        };
                        return ShellExecResult {
                            output,
                            delay_ms: 25,
                            captured_indicators: Vec::new(),
                            should_exit: false,
                        };
                    } else {
                        self.last_exit_code = 2;
                        return ShellExecResult {
                            output: format!(
                                "ls: cannot access '{target_arg}': No such file or directory"
                            ),
                            delay_ms: 25,
                            captured_indicators: Vec::new(),
                            should_exit: false,
                        };
                    }
                }

                let mut entries = if resolved == "/home" && self.user != "root" {
                    vec![self.user.clone()]
                } else {
                    self.persona
                        .ssh_vfs
                        .directories
                        .get(&mapped_resolved)
                        .cloned()
                        .unwrap_or_default()
                };

                for cow_path in self.cow_files.keys().chain(self.cow_dirs.iter()) {
                    if let Some(rel) = cow_path.strip_prefix(&prefix) {
                        let first_seg = rel.split('/').next().unwrap_or("");
                        if !first_seg.is_empty() && !entries.contains(&first_seg.to_string()) {
                            entries.push(first_seg.to_string());
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
                        let mapped_full = self.map_to_persona_path(&full);
                        let is_dir = self.persona.ssh_vfs.directories.contains_key(&mapped_full)
                            || self.cow_dirs.contains(&full);
                        let is_proc_entry = full.starts_with("/proc/");
                        let perms = if full == "/tmp" {
                            "drwxrwxrwt"
                        } else if is_dir && is_proc_entry {
                            "dr-xr-xr-x"
                        } else if is_dir {
                            "drwxr-xr-x"
                        } else if is_proc_entry {
                            "-r--r--r--"
                        } else {
                            "-rw-r--r--"
                        };
                        let owner = if (full.starts_with("/home/") && full != "/home")
                            || self.cow_files.contains_key(&full)
                        {
                            self.user.as_str()
                        } else {
                            "root"
                        };
                        let size = if is_proc_entry {
                            0
                        } else if is_dir {
                            4096
                        } else {
                            self.read_vfs_file(&full)
                                .map(|c| c.len())
                                .unwrap_or(4096)
                        };
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
                let mut skip_idx = None;
                for (i, &arg) in args.iter().enumerate() {
                    if arg == "-n" {
                        if let Some(n_str) = args.get(i + 1) {
                            count = n_str.parse().unwrap_or(10);
                            skip_idx = Some(i + 1);
                        }
                    } else if let Some(n_str) = arg.strip_prefix("-n") {
                        count = n_str.parse().unwrap_or(10);
                    } else if let Some(n_str) = arg.strip_prefix('-') {
                        if let Ok(n) = n_str.parse::<usize>() {
                            count = n;
                        }
                    }
                }
                let file_arg = args
                    .iter()
                    .enumerate()
                    .find(|(idx, a)| Some(*idx) != skip_idx && !a.starts_with('-'))
                    .map(|(_, &a)| a);
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
                let file_arg = args.iter().copied().find(|a| !a.starts_with('-'));
                let owned_text;
                let text = if let Some(f) = file_arg {
                    let resolved = self.resolve_path(f);
                    owned_text = self.read_vfs_file(&resolved).unwrap_or_default();
                    owned_text.as_str()
                } else {
                    stdin_input.unwrap_or("")
                };
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
            "mkdir" => {
                for &d in args.iter().filter(|a| !a.starts_with('-')) {
                    if self.cow_dirs.len() < MAX_COW_FILES {
                        let resolved = self.resolve_path(d);
                        self.cow_dirs.insert(resolved);
                    }
                }
                ShellExecResult {
                    output: String::new(),
                    delay_ms: 25,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "cp" | "mv" => {
                let non_flags: Vec<&str> =
                    args.iter().copied().filter(|a| !a.starts_with('-')).collect();
                if non_flags.len() >= 2 {
                    let src = self.resolve_path(non_flags[0]);
                    let dst = self.resolve_path(non_flags[1]);
                    if let Some(content) = self.read_vfs_file(&src) {
                        self.write_cow_file(&dst, &content, false);
                    }
                    if prog == "mv" {
                        self.cow_files.remove(&src);
                    }
                }
                ShellExecResult {
                    output: String::new(),
                    delay_ms: 30,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "chmod" | "chown" | "ln" | "tar" | "gzip" | "unzip" | "kill" | "pkill" | "killall" => {
                ShellExecResult {
                    output: String::new(),
                    delay_ms: 35,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
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
            format!("/home/{}", self.user)
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

fn is_valid_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Split `;` and `&&` at the top level (ignoring delimiters inside `(...)`, quotes, or backticks).
/// Returns `(subcommand, requires_previous_exit_code_zero)`.
fn split_chained_commands(line: &str) -> Vec<(&str, bool)> {
    let bytes = line.as_bytes();
    let mut result = Vec::new();
    let mut start = 0usize;
    let mut paren_depth = 0i32;
    let mut in_single = false;
    let mut in_double = false;
    let mut in_backtick = false;
    let mut req_zero = false;
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\'' && !in_double && !in_backtick {
            in_single = !in_single;
        } else if b == b'"' && !in_single && !in_backtick {
            in_double = !in_double;
        } else if b == b'`' && !in_single {
            in_backtick = !in_backtick;
        } else if !in_single && !in_double && !in_backtick {
            if b == b'(' {
                paren_depth += 1;
            } else if b == b')' && paren_depth > 0 {
                paren_depth -= 1;
            } else if paren_depth == 0 {
                if b == b';' {
                    result.push((&line[start..i], req_zero));
                    req_zero = false;
                    start = i + 1;
                } else if b == b'&' && i + 1 < bytes.len() && bytes[i + 1] == b'&' {
                    result.push((&line[start..i], req_zero));
                    req_zero = true;
                    i += 1;
                    start = i + 1;
                }
            }
        }
        i += 1;
    }
    if start <= bytes.len() {
        result.push((&line[start..], req_zero));
    }
    result
}

fn split_top_level_pipes(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut result = Vec::new();
    let mut start = 0usize;
    let mut paren_depth = 0i32;
    let mut in_single = false;
    let mut in_double = false;
    let mut in_backtick = false;

    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\'' && !in_double && !in_backtick {
            in_single = !in_single;
        } else if b == b'"' && !in_single && !in_backtick {
            in_double = !in_double;
        } else if b == b'`' && !in_single {
            in_backtick = !in_backtick;
        } else if !in_single && !in_double && !in_backtick {
            if b == b'(' {
                paren_depth += 1;
            } else if b == b')' && paren_depth > 0 {
                paren_depth -= 1;
            } else if paren_depth == 0 && b == b'|' {
                result.push(line[start..i].trim());
                start = i + 1;
            }
        }
    }
    result.push(line[start..].trim());
    result
}

fn find_command_substitution(s: &str) -> Option<(usize, usize, String)> {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
            // Check if this is arithmetic `$((` rather than command substitution `$(`
            if i + 2 < bytes.len() && bytes[i + 2] == b'(' {
                i += 3;
                continue;
            }
            let mut depth = 1i32;
            let mut j = i + 2;
            while j < bytes.len() {
                if bytes[j] == b'(' {
                    depth += 1;
                } else if bytes[j] == b')' {
                    depth -= 1;
                    if depth == 0 {
                        let inner = s[i + 2..j].to_string();
                        return Some((i, j + 1, inner));
                    }
                }
                j += 1;
            }
        } else if bytes[i] == b'`' {
            if let Some(rel_end) = s[i + 1..].find('`') {
                let end = i + 1 + rel_end;
                let inner = s[i + 1..end].to_string();
                return Some((i, end + 1, inner));
            }
        }
        i += 1;
    }
    None
}

fn find_arithmetic_expansion(s: &str) -> Option<(usize, usize, String)> {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i + 2 < bytes.len() {
        if bytes[i] == b'$' && bytes[i + 1] == b'(' && bytes[i + 2] == b'(' {
            let mut depth = 2i32;
            let mut j = i + 3;
            while j < bytes.len() {
                if bytes[j] == b'(' {
                    depth += 1;
                } else if bytes[j] == b')' {
                    depth -= 1;
                    if depth == 0 && j >= i + 4 && bytes[j - 1] == b')' {
                        let inner = s[i + 3..j - 1].to_string();
                        return Some((i, j + 1, inner));
                    }
                }
                j += 1;
            }
        }
        i += 1;
    }
    None
}

fn eval_arith_expr(expr: &str, env_vars: &HashMap<String, String>) -> i128 {
    struct Parser<'a> {
        bytes: &'a [u8],
        pos: usize,
        env: &'a HashMap<String, String>,
    }

    impl<'a> Parser<'a> {
        fn skip_ws(&mut self) {
            while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
                self.pos += 1;
            }
        }

        fn parse_expr(&mut self) -> i128 {
            let mut left = self.parse_term();
            loop {
                self.skip_ws();
                if self.pos >= self.bytes.len() {
                    break;
                }
                match self.bytes[self.pos] {
                    b'+' => {
                        self.pos += 1;
                        left = left.saturating_add(self.parse_term());
                    }
                    b'-' => {
                        self.pos += 1;
                        left = left.saturating_sub(self.parse_term());
                    }
                    _ => break,
                }
            }
            left
        }

        fn parse_term(&mut self) -> i128 {
            let mut left = self.parse_factor();
            loop {
                self.skip_ws();
                if self.pos >= self.bytes.len() {
                    break;
                }
                match self.bytes[self.pos] {
                    b'*' => {
                        self.pos += 1;
                        left = left.saturating_mul(self.parse_factor());
                    }
                    b'/' => {
                        self.pos += 1;
                        let right = self.parse_factor();
                        left = if right == 0 { 0 } else { left / right };
                    }
                    b'%' => {
                        self.pos += 1;
                        let right = self.parse_factor();
                        left = if right == 0 { 0 } else { left % right };
                    }
                    _ => break,
                }
            }
            left
        }

        fn parse_factor(&mut self) -> i128 {
            self.skip_ws();
            if self.pos >= self.bytes.len() {
                return 0;
            }
            match self.bytes[self.pos] {
                b'+' => {
                    self.pos += 1;
                    self.parse_factor()
                }
                b'-' => {
                    self.pos += 1;
                    self.parse_factor().saturating_neg()
                }
                b'(' => {
                    self.pos += 1;
                    let val = self.parse_expr();
                    self.skip_ws();
                    if self.pos < self.bytes.len() && self.bytes[self.pos] == b')' {
                        self.pos += 1;
                    }
                    val
                }
                _ => {
                    if self.bytes[self.pos] == b'$' {
                        self.pos += 1;
                    }
                    let start = self.pos;
                    while self.pos < self.bytes.len()
                        && (self.bytes[self.pos].is_ascii_alphanumeric()
                            || self.bytes[self.pos] == b'_')
                    {
                        self.pos += 1;
                    }
                    if start == self.pos {
                        return 0;
                    }
                    let token = std::str::from_utf8(&self.bytes[start..self.pos]).unwrap_or("");
                    if let Ok(num) = token.parse::<i128>() {
                        num
                    } else if let Some(val_str) = self.env.get(token) {
                        val_str.trim().parse::<i128>().unwrap_or(0)
                    } else {
                        0
                    }
                }
            }
        }
    }

    if expr.len() > 256 {
        return 0;
    }
    let mut parser = Parser {
        bytes: expr.as_bytes(),
        pos: 0,
        env: env_vars,
    };
    parser.parse_expr()
}

fn format_date_with_spec(spec: &str, now_ns: u64) -> String {
    let secs = now_ns / 1_000_000_000;
    let nanos = now_ns % 1_000_000_000;
    let (year, month, day, _wday) = civil_from_days((secs / 86400) as i64);
    let rem = secs % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;

    let mut out = spec.trim_matches('"').trim_matches('\'').to_string();
    out = out.replace("%s%N", &now_ns.to_string());
    out = out.replace("%s", &secs.to_string());
    out = out.replace("%N", &format!("{nanos:09}"));
    out = out.replace("%Y", &format!("{year:04}"));
    out = out.replace("%m", &format!("{month:02}"));
    out = out.replace("%d", &format!("{day:02}"));
    out = out.replace("%H", &format!("{h:02}"));
    out = out.replace("%M", &format!("{m:02}"));
    out = out.replace("%S", &format!("{s:02}"));
    out = out.replace("%F", &format!("{year:04}-{month:02}-{day:02}"));
    out = out.replace("%T", &format!("{h:02}:{m:02}:{s:02}"));
    out
}

fn format_utc_date_from_ns(now_ns: u64) -> String {
    let secs = now_ns / 1_000_000_000;
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
