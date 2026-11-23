pub mod config;
pub mod engine;
pub mod guard;
pub mod persona;
pub mod shell;

pub use config::{MirageConfig, ResponseAction, SigilFilterConfig, SshProxyConfig};
pub use engine::{
    ConnPermit, HoneypotPermit, MirageEngine, MirageMetricsSnapshot, PreAuthPermit,
    SshAuthDecision, TarpitPermit, ThreatEvent,
};
pub use guard::{GuardVerdict, IpGuardTable, ThreatCategory};
pub use persona::{
    PersonaSnapshot, PostgresPersonaData, PrebakedPersona, RedisPersonaData, SshVfsData,
};
pub use shell::{FakeShellSession, ShellExecResult};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_deterministic_persona_sharding_and_rotation() {
        let mut cfg = MirageConfig::default();
        cfg.persona_slots = 8;
        let engine = MirageEngine::new(cfg);

        let ip1: IpAddr = "203.0.113.10".parse().unwrap();
        let ip2_same_subnet: IpAddr = "203.0.113.250".parse().unwrap();

        let p1 = engine.select_persona(ip1);
        let p2 = engine.select_persona(ip2_same_subnet);

        assert_eq!(p1.epoch_id, 1);
        assert_eq!(p1.slot_id, p2.slot_id);
        assert_eq!(p1.hostname, p2.hostname);
        assert_eq!(p1.ssh_banner, p2.ssh_banner);

        let stable_key_before = engine.honeypot_host_key_seed();
        let new_snap = engine.rotate_now();
        assert_eq!(new_snap.epoch_id, 2);
        assert_eq!(engine.honeypot_host_key_seed(), stable_key_before);

        let p1_after = engine.select_persona(ip1);
        assert_eq!(p1_after.epoch_id, 2);
    }

    #[test]
    fn test_ip_guard_anti_cc_and_configurable_bruteforce_policy() {
        let mut cfg = MirageConfig::default();
        cfg.ssh.max_connections_per_ip = 2;
        cfg.ssh.bruteforce_short_sessions_threshold = 3;
        cfg.ssh.max_conns_per_ip_window = 20;
        cfg.ssh.bruteforce_action = ResponseAction::Fail2ban;
        cfg.ssh.cve_exploit_action = ResponseAction::SshHoneypot;
        cfg.ssh.scanner_action = ResponseAction::EndlesshTarpit;
        let engine = MirageEngine::new(cfg);

        assert_eq!(
            engine.action_for(ThreatCategory::BruteForce),
            ResponseAction::Fail2ban
        );
        assert_eq!(
            engine.action_for(ThreatCategory::CveExploit),
            ResponseAction::SshHoneypot
        );
        assert_eq!(
            engine.action_for(ThreatCategory::Scanner),
            ResponseAction::EndlesshTarpit
        );

        let attacker: IpAddr = "198.51.100.77".parse().unwrap();

        // 1. Concurrent per-IP cap drops 3rd simultaneous connection immediately (anti-CC)
        let (v1, p1) = engine.evaluate_incoming_connection(attacker);
        let (v2, p2) = engine.evaluate_incoming_connection(attacker);
        let (v3, p3) = engine.evaluate_incoming_connection(attacker);
        assert_eq!(v1, GuardVerdict::InspectAndProxy);
        assert_eq!(v2, GuardVerdict::InspectAndProxy);
        assert!(matches!(v3, GuardVerdict::DropOverloaded(_)));
        assert!(p3.is_none());
        drop(p1);
        drop(p2);

        // 2. Three short-lived upstream sessions trigger BruteForce quarantine
        assert!(!engine.record_short_upstream_session(attacker));
        assert!(!engine.record_short_upstream_session(attacker));
        assert!(engine.record_short_upstream_session(attacker));

        let (v4, _p4) = engine.evaluate_incoming_connection(attacker);
        assert!(matches!(
            v4,
            GuardVerdict::Quarantined {
                category: ThreatCategory::BruteForce,
                ..
            }
        ));
    }

    #[test]
    fn test_full_linux_fake_shell_pipes_cow_and_tools() {
        let cfg = MirageConfig::default();
        let engine = MirageEngine::new(cfg);
        let persona = engine.select_persona("192.0.2.99".parse().unwrap());

        let mut shell = FakeShellSession::new(persona.clone(), None);

        let pipe_res = shell.execute_line("cat /etc/passwd | grep bash");
        assert!(pipe_res.output.contains("root:x:0:0"));
        assert!(pipe_res.output.contains(&persona.ssh_vfs.default_user));
        assert!(!pipe_res.output.contains("nologin"));

        let redir_res =
            shell.execute_line("echo \"ssh-ed25519 AAAA_ATTACKER_KEY\" >> ~/.ssh/authorized_keys");
        assert!(redir_res
            .captured_indicators
            .iter()
            .any(|i| i.starts_with("file_write:")));

        let read_back = shell.execute_line("cat ~/.ssh/authorized_keys");
        assert!(read_back.output.contains("AAAA_ATTACKER_KEY"));

        assert_eq!(shell.execute_line("nproc").output.trim(), "64");
        assert_eq!(shell.execute_line("arch").output.trim(), "x86_64");
        let cut_res = shell.execute_line("cat /etc/passwd | grep root | cut -d: -f1");
        assert_eq!(cut_res.output.trim(), "root");

        // Verify 6-point realism criteria:
        // 1. Version consistency with OpenSSH_10.6 (no Ubuntu 22.04 mismatch)
        let arch_shell = FakeShellSession::new(persona.clone(), Some("devops"))
            .with_session_context("SSH-2.0-OpenSSH_10.6", "172.16.36.36".parse().unwrap());
        assert!(!arch_shell.welcome_banner().contains("Ubuntu 22.04"));
        let mut arch_shell = arch_shell;
        assert!(arch_shell.execute_line("uname -a").output.contains("arch1-1"));
        // 2. Filesystem root has /proc, /sys and varied timestamps
        let ls_root = arch_shell.execute_line("ls -la /");
        assert!(ls_root.output.contains("proc") && ls_root.output.contains("sys"));
        // 3. Piped ls outputs 1 entry per line (`ls / | wc -l` == 17)
        assert_eq!(arch_shell.execute_line("ls / | wc -l").output.trim(), "17");
        // 4. Timing (`time sleep 1` waits ~1000ms and prints real/user/sys)
        let timed = arch_shell.execute_line("time sleep 1");
        assert_eq!(timed.delay_ms, 1000);
        assert!(timed.output.contains("real\t0m1.000s"));
        // 5. Session state (`cd /tmp && pwd`, `who` shows attacker IP)
        assert_eq!(arch_shell.execute_line("cd /tmp && pwd").output.trim(), "/tmp");
        assert!(arch_shell.execute_line("who").output.contains("172.16.36.36"));
        // 6. Adversarial systemd (`systemctl status nonexistent` -> not found)
        let bad_unit = arch_shell.execute_line("systemctl status nonexistent");
        assert!(bad_unit.output.contains("could not be found"));

        // 7. Red-team 5 shell realism probes:
        // (a) Command substitution `$(date +%s%N)`, virtual clock advancement across `sleep 2`,
        //     arithmetic `$(( (E-S)/1000000 ))`, and `$RANDOM` expansion
        let timing_probe = arch_shell.execute_line(
            "S=$(date +%s%N); sleep 2; E=$(date +%s%N); echo DELTA_MS=$(( (E-S)/1000000 ))",
        );
        assert!(
            timing_probe.output.trim().starts_with("DELTA_MS="),
            "unexpected output: {}",
            timing_probe.output
        );
        let delta_val: i64 = timing_probe
            .output
            .trim()
            .trim_start_matches("DELTA_MS=")
            .parse()
            .expect("numeric DELTA_MS");
        assert!(
            (1950..=2150).contains(&delta_val),
            "expected ~2000ms delta, got {delta_val}"
        );

        let r1 = arch_shell.execute_line("echo $RANDOM").output;
        let r2 = arch_shell.execute_line("echo $RANDOM").output;
        assert!(r1.trim().parse::<u16>().is_ok());
        assert!(r2.trim().parse::<u16>().is_ok());
        assert_ne!(r1.trim(), r2.trim());

        // (b) Pipe `ls / | head -3` outputs 3 lines; `head -6 /etc/passwd` outputs 6 lines
        let head3 = arch_shell.execute_line("ls / | head -3");
        assert_eq!(head3.output.lines().count(), 3);
        let head6_passwd = arch_shell.execute_line("head -6 /etc/passwd");
        assert_eq!(head6_passwd.output.lines().count(), 6);

        // (c) `/proc` has `dr-xr-xr-x` directories for PIDs and size 0 for virtual files,
        //     and `/proc/loadavg` matches `w` load average
        let ls_proc = arch_shell.execute_line("ls -la /proc");
        assert!(
            ls_proc.output.lines().any(|l| l.starts_with("dr-xr-xr-x") && l.ends_with(" 1")),
            "expected /proc/1 directory in:\n{}",
            ls_proc.output
        );
        assert!(
            ls_proc
                .output
                .lines()
                .any(|l| l.starts_with("-r--r--r--") && l.contains("     0 ") && l.ends_with(" cpuinfo")),
            "expected 0-byte /proc/cpuinfo in:\n{}",
            ls_proc.output
        );
        let loadavg_txt = arch_shell.execute_line("cat /proc/loadavg").output;
        let load_first3: Vec<&str> = loadavg_txt.split_whitespace().take(3).collect();
        let w_out = arch_shell.execute_line("w").output;
        assert!(
            w_out.contains(&format!(
                "load average: {}, {}, {}",
                load_first3[0], load_first3[1], load_first3[2]
            )),
            "mismatch between /proc/loadavg ({loadavg_txt}) and w ({w_out})"
        );

        // (d) Identity & OS process consistency: logged in as `devops` on Arch (`OpenSSH_10.6`),
        //     `$HOME` is `/home/devops`, `/etc/passwd` has `devops:x:1000:1000`, and `ps aux`
        //     has no Debian-specific `/usr/lib/postgresql/14` or `php-fpm`
        assert_eq!(arch_shell.execute_line("echo $HOME").output.trim(), "/home/devops");
        let passwd_devops = arch_shell.execute_line("grep devops /etc/passwd").output;
        assert!(passwd_devops.contains("devops:x:1000:1000:"));
        assert!(passwd_devops.contains(":/home/devops:/bin/bash"));
        let ps_out = arch_shell.execute_line("ps aux").output;
        assert!(!ps_out.contains("/usr/lib/postgresql/14"));
        assert!(!ps_out.contains("php-fpm"));
        assert!(ps_out.contains("devops"));

        // (e) Single-file `ls -la /tmp/zz_probe` after `touch /tmp/zz_probe`
        let touch_ls =
            arch_shell.execute_line("touch /tmp/zz_probe && ls -la /tmp/zz_probe");
        assert_eq!(
            touch_ls.output.lines().count(),
            1,
            "expected single file line, got:\n{}",
            touch_ls.output
        );
        assert!(touch_ls.output.contains("/tmp/zz_probe"));
        assert!(!touch_ls.output.contains("total "));
        let missing_ls = arch_shell.execute_line("ls -la /tmp/does_not_exist_999");
        assert!(missing_ls.output.contains("No such file or directory"));
    }
}
