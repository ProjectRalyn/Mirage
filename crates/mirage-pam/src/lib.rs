//! Linux PAM Shared Library (`libpam_mirage.so`) for Native OpenSSH Integration.
//!
//! Mount directly in `/etc/pam.d/sshd` BEFORE `pam_unix.so`:
//! ```text
//! auth sufficient /usr/local/lib/security/libpam_mirage.so \
//!     decoy_users=svc_deploy,admin,test,ubnt,postgres \
//!     accept_on=3 fail_delay_ms=1200 log_file=/var/log/mirage-pam.jsonl
//! ```
//!
//! Safety guarantee:
//! - For any username NOT listed in `decoy_users`, `pam_sm_authenticate` immediately returns
//!   `PAM_IGNORE (25)` so real administrators authenticate normally via standard OpenSSH PAM / keys.
//! - For listed `decoy_users` (paired with `ForceCommand /usr/local/bin/mirage-fake-shell` in
//!   `/etc/ssh/sshd_config`), `libpam_mirage.so` logs every guessed password, delays attempts
//!   `1..N-1` (`PAM_AUTH_ERR`), and returns `PAM_SUCCESS` on attempt `N` (or immediately if the
//!   attacker used the rotating password leaked in `/.env` or `/wp-config.php.bak`).

use libc::{c_char, c_int, c_void};
use mirage_core::{MirageConfig, MirageEngine};
use std::ffi::CStr;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Standard Linux PAM return codes and item types (`/usr/include/security/_pam_types.h`)
pub const PAM_SUCCESS: c_int = 0;
pub const PAM_AUTH_ERR: c_int = 7;
pub const PAM_IGNORE: c_int = 25;

const PAM_RHOST: c_int = 4;
const PAM_AUTHTOK: c_int = 6;

#[link(name = "pam")]
extern "C" {
    fn pam_get_user(
        pamh: *mut c_void,
        user: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;

    fn pam_get_item(
        pamh: *const c_void,
        item_type: c_int,
        item: *mut *const c_void,
    ) -> c_int;

    fn pam_get_authtok(
        pamh: *mut c_void,
        item: c_int,
        authtok: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;
}

/// Parsed options passed to `libpam_mirage.so` via `/etc/pam.d/sshd` module arguments.
#[derive(Debug, Clone)]
pub struct PamMirageOptions {
    pub decoy_users: Vec<String>,
    pub accept_on: u32,
    pub fail_delay_ms: u64,
    pub config_path: Option<PathBuf>,
    pub state_dir: PathBuf,
    pub log_file: PathBuf,
}

impl Default for PamMirageOptions {
    fn default() -> Self {
        Self {
            decoy_users: vec![
                "svc_deploy".to_string(),
                "admin".to_string(),
                "test".to_string(),
                "ubnt".to_string(),
                "postgres".to_string(),
            ],
            accept_on: 3,
            fail_delay_ms: 1200,
            config_path: None,
            state_dir: PathBuf::from("/tmp/mirage-pam-state"),
            log_file: PathBuf::from("/tmp/mirage-pam.jsonl"),
        }
    }
}

impl PamMirageOptions {
    pub fn parse_args(args: &[String]) -> Self {
        let mut opts = Self::default();
        for arg in args {
            if let Some(val) = arg.strip_prefix("decoy_users=") {
                opts.decoy_users = val
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            } else if let Some(val) = arg.strip_prefix("accept_on=") {
                if let Ok(n) = val.parse::<u32>() {
                    opts.accept_on = n;
                }
            } else if let Some(val) = arg.strip_prefix("fail_delay_ms=") {
                if let Ok(ms) = val.parse::<u64>() {
                    opts.fail_delay_ms = ms;
                }
            } else if let Some(val) = arg.strip_prefix("config=") {
                opts.config_path = Some(PathBuf::from(val));
            } else if let Some(val) = arg.strip_prefix("state_dir=") {
                opts.state_dir = PathBuf::from(val);
            } else if let Some(val) = arg.strip_prefix("log_file=") {
                opts.log_file = PathBuf::from(val);
            }
        }
        opts
    }

    pub fn is_decoy_user(&self, user: &str) -> bool {
        self.decoy_users.iter().any(|u| u == user)
    }
}

/// Core authentication evaluator shared by the C PAM entry point and Rust unit tests.
pub fn evaluate_pam_auth(
    opts: &PamMirageOptions,
    username: &str,
    rhost: &str,
    password: &str,
) -> c_int {
    // 1. Real users are NEVER intercepted by the honeypot PAM module!
    if !opts.is_decoy_user(username) {
        return PAM_IGNORE;
    }

    // 2. Check cross-protocol leaked credentials for the current time-based rotation epoch
    let matches_leaked_secret = check_leaked_credential(opts, rhost, password);

    // 3. Increment cross-process attempt counter for `(rhost, username)`
    let attempt = increment_attempt_counter(&opts.state_dir, rhost, username);

    let accepted =
        matches_leaked_secret || (opts.accept_on > 0 && attempt >= opts.accept_on);

    let decision = if matches_leaked_secret {
        "ACCEPT_STOLEN_CREDENTIAL"
    } else if accepted {
        "ACCEPT_NTH_ATTEMPT_INTO_FAKE_SHELL"
    } else {
        "REJECT_WITH_TARPIT_DELAY"
    };

    append_pam_telemetry(&opts.log_file, rhost, username, password, attempt, decision);

    if accepted {
        // Reset counter after letting them in so future sessions repeat the N-attempt cycle
        let _ = reset_attempt_counter(&opts.state_dir, rhost, username);
        PAM_SUCCESS
    } else {
        if opts.fail_delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(opts.fail_delay_ms));
        }
        PAM_AUTH_ERR
    }
}

fn check_leaked_credential(opts: &PamMirageOptions, rhost: &str, password: &str) -> bool {
    if password.is_empty() {
        return false;
    }
    let mut cfg = opts
        .config_path
        .as_ref()
        .and_then(|p| MirageConfig::from_toml_file(p).ok())
        .unwrap_or_default();

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let interval = cfg.rotation_interval_secs.max(1);
    let time_epoch = (now_secs / interval) + 1;
    cfg.master_seed = cfg.master_seed.wrapping_add(time_epoch);

    let engine = MirageEngine::new(cfg);
    let ip: IpAddr = rhost
        .parse()
        .unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
    let persona = engine.select_persona(ip);

    password == persona.postgres_data.db_password || password == persona.redis_data.require_pass
}

fn counter_file_path(state_dir: &Path, rhost: &str, username: &str) -> PathBuf {
    let safe_key: String = format!("{rhost}_{username}")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    state_dir.join(format!("cnt_{safe_key}.txt"))
}

fn increment_attempt_counter(state_dir: &Path, rhost: &str, username: &str) -> u32 {
    let _ = fs::create_dir_all(state_dir);
    let path = counter_file_path(state_dir, rhost, username);
    let prev: u32 = fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let next = prev.saturating_add(1);
    let _ = fs::write(&path, next.to_string());
    next
}

fn reset_attempt_counter(state_dir: &Path, rhost: &str, username: &str) -> std::io::Result<()> {
    let path = counter_file_path(state_dir, rhost, username);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn append_pam_telemetry(
    log_file: &Path,
    rhost: &str,
    username: &str,
    password: &str,
    attempt: u32,
    decision: &str,
) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let entry = serde_json::json!({
        "timestamp_unix": ts,
        "protocol": "OPENSSH-PAM-SO",
        "client_ip": rhost,
        "username": username,
        "password_guess": password,
        "attempt": attempt,
        "decision": decision,
    });
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_file) {
        let _ = writeln!(file, "{entry}");
    }
}

unsafe fn parse_c_argv(argc: c_int, argv: *const *const c_char) -> Vec<String> {
    let mut out = Vec::new();
    if argc <= 0 || argv.is_null() {
        return out;
    }
    for i in 0..(argc as isize) {
        let ptr = *argv.offset(i);
        if !ptr.is_null() {
            if let Ok(s) = CStr::from_ptr(ptr).to_str() {
                out.push(s.to_string());
            }
        }
    }
    out
}

/// Standard Linux PAM entry point called by OpenSSH `sshd` during authentication.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut c_void,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    if pamh.is_null() {
        return PAM_IGNORE;
    }
    let result = std::panic::catch_unwind(|| {
        let args = parse_c_argv(argc, argv);
        let opts = PamMirageOptions::parse_args(&args);

        // 1. Read username from PAM handle
        let mut user_ptr: *const c_char = ptr::null();
        if pam_get_user(pamh, &mut user_ptr, ptr::null()) != PAM_SUCCESS || user_ptr.is_null() {
            return PAM_IGNORE;
        }
        let username = CStr::from_ptr(user_ptr).to_string_lossy().into_owned();

        // Fast-path exit for real users before reading password or touching disk
        if !opts.is_decoy_user(&username) {
            return PAM_IGNORE;
        }

        // 2. Read attacker IP from PAM_RHOST
        let mut rhost_ptr: *const c_void = ptr::null();
        let rhost = if pam_get_item(pamh, PAM_RHOST, &mut rhost_ptr) == PAM_SUCCESS
            && !rhost_ptr.is_null()
        {
            CStr::from_ptr(rhost_ptr as *const c_char)
                .to_string_lossy()
                .into_owned()
        } else {
            "unknown".to_string()
        };

        // 3. Read guessed password via pam_get_authtok (falls back to pam_get_item PAM_AUTHTOK)
        let mut pass_ptr: *const c_char = ptr::null();
        let password = if pam_get_authtok(pamh, PAM_AUTHTOK, &mut pass_ptr, ptr::null())
            == PAM_SUCCESS
            && !pass_ptr.is_null()
        {
            CStr::from_ptr(pass_ptr).to_string_lossy().into_owned()
        } else {
            let mut item_ptr: *const c_void = ptr::null();
            if pam_get_item(pamh, PAM_AUTHTOK, &mut item_ptr) == PAM_SUCCESS && !item_ptr.is_null()
            {
                CStr::from_ptr(item_ptr as *const c_char)
                    .to_string_lossy()
                    .into_owned()
            } else {
                String::new()
            }
        };

        evaluate_pam_auth(&opts, &username, &rhost, &password)
    });

    result.unwrap_or(PAM_IGNORE)
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    pamh: *mut c_void,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    if pamh.is_null() {
        return PAM_IGNORE;
    }
    let result = std::panic::catch_unwind(|| {
        let args = parse_c_argv(argc, argv);
        let opts = PamMirageOptions::parse_args(&args);
        let mut user_ptr: *const c_char = ptr::null();
        if pam_get_user(pamh, &mut user_ptr, ptr::null()) != PAM_SUCCESS || user_ptr.is_null() {
            return PAM_IGNORE;
        }
        let username = CStr::from_ptr(user_ptr).to_string_lossy();
        if opts.is_decoy_user(&username) {
            PAM_SUCCESS
        } else {
            PAM_IGNORE
        }
    });
    result.unwrap_or(PAM_IGNORE)
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_open_session(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_close_session(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pam_ignores_real_users_and_accepts_decoy_on_nth_attempt() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "mirage_pam_test_{}",
            std::process::id()
        ));
        let log_file = tmp_dir.join("pam.jsonl");
        let _ = fs::remove_dir_all(&tmp_dir);

        let args = vec![
            "decoy_users=svc_deploy,admin".to_string(),
            "accept_on=3".to_string(),
            "fail_delay_ms=5".to_string(),
            format!("state_dir={}", tmp_dir.display()),
            format!("log_file={}", log_file.display()),
        ];
        let opts = PamMirageOptions::parse_args(&args);

        // 1. Real user ("arthur") is NEVER intercepted -> PAM_IGNORE
        assert_eq!(
            evaluate_pam_auth(&opts, "arthur", "10.0.0.5", "real_pass"),
            PAM_IGNORE
        );

        // 2. Decoy user ("svc_deploy") fails attempts 1 & 2, succeeds on attempt 3
        assert_eq!(
            evaluate_pam_auth(&opts, "svc_deploy", "203.0.113.88", "123456"),
            PAM_AUTH_ERR
        );
        assert_eq!(
            evaluate_pam_auth(&opts, "svc_deploy", "203.0.113.88", "password"),
            PAM_AUTH_ERR
        );
        assert_eq!(
            evaluate_pam_auth(&opts, "svc_deploy", "203.0.113.88", "admin2026"),
            PAM_SUCCESS
        );

        // 3. Verify JSONL telemetry captured all 3 attempts
        let logged = fs::read_to_string(&log_file).unwrap();
        assert_eq!(logged.lines().count(), 3);
        assert!(logged.contains("admin2026"));
        assert!(logged.contains("ACCEPT_NTH_ATTEMPT_INTO_FAKE_SHELL"));

        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
