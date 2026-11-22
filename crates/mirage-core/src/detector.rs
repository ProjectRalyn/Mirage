use crate::config::{HttpHoneypotConfig, SigilFilterConfig};
use crate::persona::PrebakedPersona;
use serde::Serialize;
use sigil_filter::{Sigil, ViolationCategory};

/// Lightweight view of an incoming HTTP request for zero-copy classification.
#[derive(Debug, Clone)]
pub struct HttpRequestView<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    /// Selected HTTP header `(name, value)` pairs inspected by `sigil-filter`
    /// (e.g. `User-Agent`, `Referer`, `Cookie`, `X-Api-Version`, `X-Forwarded-Host`).
    pub header_samples: &'a [(&'a str, &'a str)],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TarpitKind {
    GzipSqlBackup,
    JavaHprof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LfiTargetHint {
    EtcPasswd,
    ProcSelfEnviron,
    DotEnv,
}

/// Classification verdict for an incoming HTTP request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum TrapVerdict {
    /// Benign request; pass through to the inner service or upstream backend.
    PassThrough,
    /// Fake WordPress login page (`GET` renders login form, `POST` delays + returns authentic WP error).
    WordPressLogin { is_post_attempt: bool },
    /// Fake `/wp-json/` REST root discovery document.
    WordPressRestIndex,
    /// Fake `/wp-json/wp/v2/users` enumeration response.
    WordPressUsersJson,
    /// Fake `/wp-json/wp/v2/posts` internal runbook leak response.
    WordPressPostsJson,
    /// Fake `/xmlrpc.php` response with artificial delay.
    WordPressXmlRpc,
    /// Fake `/wp-config.php.bak` or `.wp-config.php.swp` backup leak.
    WordPressConfigBackup,
    /// Fake `/wp-content/debug.log` PHP stack trace & credential leak.
    WordPressDebugLog,
    /// Fake `/wp-admin/admin-ajax.php` plugin AJAX response.
    WordPressAdminAjax,
    /// Fake `/readme.html` WordPress version disclosure page.
    WordPressReadme,
    /// Fake `.env` credentials leak.
    DotEnvLeak,
    /// Fake `.git/config` repository credentials leak.
    GitConfigLeak,
    /// Fake `.git/HEAD` ref leak.
    GitHeadLeak,
    /// Fake Spring Boot `/actuator/env` configuration leak.
    SpringActuatorEnv,
    /// Fake `phpinfo()` diagnostic page leaking environment variables.
    PhpInfo,
    /// Fake GraphQL introspection schema with bait fields.
    GraphqlIntrospection,
    /// Fake OpenAPI / Swagger JSON specification.
    OpenApiSchema,
    /// Fake debug endpoint leaking session previews and Canary URLs.
    ApiDebugEndpoint,
    /// SQL injection syntax error response (MySQL or PostgreSQL flavor).
    SqlInjectionError { is_postgres: bool },
    /// Boolean-based blind SQL injection response (True vs False page variants).
    SqlInjectionBoolean { truthy: bool },
    /// Time-based blind SQL injection response with tarpit delay.
    SqlInjectionTimeBlind { delay_ms: u64 },
    /// Endless / huge archive drip-feed stream (`Content-Length: 256MB`, dripped at a few bytes/sec).
    TarpitStream { kind: TarpitKind },

    // ---- Tailored Deception Traps driven by `sigil-filter` 12 heuristic categories ----
    /// Path Traversal / LFI (`../`, `%252e%252e`, `php://filter`) -> serves persona's fake OS file.
    PathTraversalLfi {
        target: LfiTargetHint,
        confidence_pct: u8,
    },
    /// OS Command Injection (`; id`, `$(whoami)`, `| uname -a`) -> executes in zero-overhead `FakeShellSession`!
    CommandInjectionRce {
        extracted_cmd: String,
        confidence_pct: u8,
    },
    /// SSRF (`169.254.169.254`, `gopher://`, `http://127.0.0.1`) -> serves rotating AWS IMDSv1 credentials JSON.
    SsrfCloudMetadata { confidence_pct: u8 },
    /// SSTI / Code Injection (`{{7*7}}`, `__globals__`, `Runtime.exec`) -> serves evaluated `49` + Flask config bait.
    SstiTemplateEval { confidence_pct: u8 },
    /// NoSQL Injection (`$ne`, `$where`, Mongo/Redis injection) -> serves fake MongoDB admin document array.
    NoSqlAdminDump { confidence_pct: u8 },
    /// XXE / XML / XPath Injection -> serves SOAP XML reflecting fake `/etc/passwd`.
    XxeEntityLeak { confidence_pct: u8 },
    /// Log4Shell / JNDI / Deserialization / Prototype Pollution (`${jndi:ldap://...}`, `rO0AB`, `__proto__`).
    DeserializationJndiTrap { confidence_pct: u8 },
    /// LDAP Injection -> serves fake LDIF directory dump with SSHA password hash.
    LdapDirectoryDump { confidence_pct: u8 },
    /// XSS -> serves legacy admin search page with bait non-HttpOnly session cookie.
    XssBaitPage { confidence_pct: u8 },
    /// CRLF / HTTP Header Injection -> serves fake internal proxy header debug output.
    CrlfProxyDebug { confidence_pct: u8 },
}

impl TrapVerdict {
    /// Returns true if this verdict was triggered by `sigil-filter` heuristic recognition.
    pub fn is_sigil_verdict(&self) -> bool {
        matches!(
            self,
            TrapVerdict::PathTraversalLfi { .. }
                | TrapVerdict::CommandInjectionRce { .. }
                | TrapVerdict::SsrfCloudMetadata { .. }
                | TrapVerdict::SstiTemplateEval { .. }
                | TrapVerdict::NoSqlAdminDump { .. }
                | TrapVerdict::XxeEntityLeak { .. }
                | TrapVerdict::DeserializationJndiTrap { .. }
                | TrapVerdict::LdapDirectoryDump { .. }
                | TrapVerdict::XssBaitPage { .. }
                | TrapVerdict::CrlfProxyDebug { .. }
        )
    }
}

/// Inspect an incoming HTTP request using both high-specificity path rules AND
/// `sigil-filter` (zero-allocation ~85ns benign short-circuit + multi-pass anti-obfuscation).
pub fn classify_http_request(
    req: &HttpRequestView<'_>,
    cfg: &HttpHoneypotConfig,
    sigil_cfg: &SigilFilterConfig,
    sigil: &Sigil,
    persona: &PrebakedPersona,
) -> TrapVerdict {
    let path_lower = req.path.to_ascii_lowercase();
    let decoded_query = req.query.map(percent_decode_lossy).unwrap_or_default();
    let query_upper = decoded_query.to_ascii_uppercase();

    // 1. High-specificity SQLMap blind/time/error probes in query parameters
    if cfg.enable_sqli_trap && !decoded_query.is_empty() {
        if let Some(verdict) = detect_sqli(&decoded_query, &query_upper, cfg, persona) {
            return verdict;
        }
    }

    // 2. Tarpit Archive paths (/actuator/heapdump, /backup.sql.gz, etc.)
    if cfg.enable_tarpit_archives {
        if path_lower.ends_with("/heapdump") || path_lower == "/heapdump" {
            return TrapVerdict::TarpitStream {
                kind: TarpitKind::JavaHprof,
            };
        }
        let matches_tarpit_suffix = cfg.custom_tarpit_suffixes.iter().any(|suf| {
            let s = suf.to_ascii_lowercase();
            path_lower.ends_with(&s)
        });
        if matches_tarpit_suffix {
            return TrapVerdict::TarpitStream {
                kind: TarpitKind::GzipSqlBackup,
            };
        }
    }

    // 3. Deep WordPress / CMS traps
    if cfg.enable_wordpress_trap {
        if path_lower.contains("wp-config.php")
            || path_lower.ends_with(".wp-config.php.swp")
            || path_lower.ends_with("wp-config.bak")
            || path_lower.ends_with("wp-config.old")
            || path_lower.ends_with("wp-config.txt")
        {
            return TrapVerdict::WordPressConfigBackup;
        }
        if path_lower.ends_with("/wp-content/debug.log") || path_lower.ends_with("/debug.log") {
            return TrapVerdict::WordPressDebugLog;
        }
        if path_lower.ends_with("/wp-admin/admin-ajax.php") {
            return TrapVerdict::WordPressAdminAjax;
        }
        if path_lower.ends_with("/readme.html")
            || path_lower.ends_with("/wp-includes/wlwmanifest.xml")
        {
            return TrapVerdict::WordPressReadme;
        }
        if path_lower.contains("/wp-json/wp/v2/users")
            || query_upper.contains("REST_ROUTE=/WP/V2/USERS")
            || (path_lower == "/" && query_upper.starts_with("AUTHOR="))
        {
            return TrapVerdict::WordPressUsersJson;
        }
        if path_lower.contains("/wp-json/wp/v2/posts")
            || path_lower.contains("/wp-json/wp/v2/pages")
            || query_upper.contains("REST_ROUTE=/WP/V2/POSTS")
        {
            return TrapVerdict::WordPressPostsJson;
        }
        if path_lower == "/wp-json"
            || path_lower == "/wp-json/"
            || query_upper.starts_with("REST_ROUTE=/")
        {
            return TrapVerdict::WordPressRestIndex;
        }
        if path_lower.ends_with("/xmlrpc.php") {
            return TrapVerdict::WordPressXmlRpc;
        }
        if path_lower.ends_with("/wp-login.php")
            || path_lower.starts_with("/wp-admin")
            || cfg.custom_wordpress_paths.iter().any(|p| {
                let p_low = p.to_ascii_lowercase();
                path_lower == p_low || path_lower.starts_with(&format!("{p_low}/"))
            })
        {
            return TrapVerdict::WordPressLogin {
                is_post_attempt: req.method.eq_ignore_ascii_case("POST"),
            };
        }
    }

    // 4. Secret & Configuration Leak traps
    if cfg.enable_secret_leak_trap {
        if path_lower == "/.env"
            || path_lower.starts_with("/.env.")
            || path_lower.ends_with("/.env")
        {
            return TrapVerdict::DotEnvLeak;
        }
        if path_lower.ends_with("/.git/config") {
            return TrapVerdict::GitConfigLeak;
        }
        if path_lower.ends_with("/.git/head") {
            return TrapVerdict::GitHeadLeak;
        }
        if path_lower == "/actuator/env"
            || path_lower == "/actuator"
            || path_lower.starts_with("/actuator/")
        {
            return TrapVerdict::SpringActuatorEnv;
        }
        if path_lower.ends_with("phpinfo.php") || path_lower == "/info.php" {
            return TrapVerdict::PhpInfo;
        }
        if cfg
            .custom_secret_paths
            .iter()
            .any(|p| path_lower == p.to_ascii_lowercase())
        {
            return TrapVerdict::DotEnvLeak;
        }
    }

    // 5. Vulnerable API / GraphQL / Swagger traps
    if cfg.enable_api_trap {
        if path_lower == "/graphql" || path_lower.ends_with("/graphql") {
            return TrapVerdict::GraphqlIntrospection;
        }
        if path_lower.ends_with("/swagger.json")
            || path_lower.ends_with("/openapi.json")
            || path_lower.ends_with("/api-docs")
        {
            return TrapVerdict::OpenApiSchema;
        }
        if cfg.custom_api_debug_paths.iter().any(|p| {
            let p_low = p.to_ascii_lowercase();
            path_lower == p_low || path_lower.contains(&p_low)
        }) {
            return TrapVerdict::ApiDebugEndpoint;
        }
    }

    // 6. `sigil-filter` zero-allocation heuristic inspection across path, query, and headers!
    // Catches obfuscated SQLi, Path Traversal / LFI, Command Injection, SSRF, SSTI, NoSQLi,
    // XXE, Log4Shell/JNDI, XSS, LDAPi, CRLF, and Buffer Overflow in ~85ns–1.5µs!
    if sigil_cfg.enabled {
        if let Some(verdict) = inspect_with_sigil(req, &decoded_query, cfg, sigil_cfg, sigil, persona)
        {
            return verdict;
        }
    }

    // 7. Scanner User-Agent fallback trap
    if let Some(ua) = req.user_agent {
        let ua_lower = ua.to_ascii_lowercase();
        if cfg
            .scanner_user_agents
            .iter()
            .any(|sig| ua_lower.contains(&sig.to_ascii_lowercase()))
        {
            if ua_lower.contains("wpscan") {
                return TrapVerdict::WordPressLogin {
                    is_post_attempt: false,
                };
            }
            return TrapVerdict::ApiDebugEndpoint;
        }
    }

    TrapVerdict::PassThrough
}

fn inspect_with_sigil(
    req: &HttpRequestView<'_>,
    decoded_query: &str,
    cfg: &HttpHoneypotConfig,
    sigil_cfg: &SigilFilterConfig,
    sigil: &Sigil,
    persona: &PrebakedPersona,
) -> Option<TrapVerdict> {
    // Track highest-confidence match across path, query, and inspected headers
    let mut best_match: Option<(ViolationCategory, f32, String)> = None;

    // A. Inspect raw path (sigil handles multi-pass URL/Unicode/overlong UTF-8 decoding itself!)
    let path_res = sigil.detect(req.path);
    if let Some(cat) = path_res.violation {
        best_match = Some((cat, path_res.confidence, req.path.to_string()));
    }

    // B. Inspect raw query string (if present)
    if let Some(raw_q) = req.query {
        let q_res = sigil.detect(raw_q);
        if let Some(cat) = q_res.violation {
            if best_match
                .as_ref()
                .map(|(_, c, _)| q_res.confidence > *c)
                .unwrap_or(true)
            {
                best_match = Some((cat, q_res.confidence, decoded_query.to_string()));
            }
        }
    }

    // C. Inspect suspicious HTTP headers (e.g. Log4Shell `${jndi:ldap://...}` in User-Agent / X-Api-Version)
    if sigil_cfg.inspect_headers {
        for &(_hdr_name, hdr_val) in req.header_samples {
            let h_res = sigil.detect(hdr_val);
            if let Some(cat) = h_res.violation {
                if best_match
                    .as_ref()
                    .map(|(_, c, _)| h_res.confidence > *c)
                    .unwrap_or(true)
                {
                    best_match = Some((cat, h_res.confidence, hdr_val.to_string()));
                }
            }
        }
    }

    let (category, confidence, matched_sample) = best_match?;
    let confidence_pct = (confidence * 100.0).round().clamp(0.0, 100.0) as u8;
    let sample_lower = matched_sample.to_ascii_lowercase();

    let verdict = match category {
        ViolationCategory::SqlInjection => {
            if cfg.enable_sqli_trap {
                TrapVerdict::SqlInjectionError {
                    is_postgres: persona.slot_id % 2 == 1,
                }
            } else {
                TrapVerdict::ApiDebugEndpoint
            }
        }
        ViolationCategory::PathTraversal => {
            let target = if sample_lower.contains("environ") {
                LfiTargetHint::ProcSelfEnviron
            } else if sample_lower.contains(".env") || sample_lower.contains("credentials") {
                LfiTargetHint::DotEnv
            } else {
                LfiTargetHint::EtcPasswd
            };
            TrapVerdict::PathTraversalLfi {
                target,
                confidence_pct,
            }
        }
        ViolationCategory::CommandInjection => {
            let extracted_cmd = extract_injected_command(&matched_sample);
            TrapVerdict::CommandInjectionRce {
                extracted_cmd,
                confidence_pct,
            }
        }
        ViolationCategory::Ssrf => TrapVerdict::SsrfCloudMetadata { confidence_pct },
        ViolationCategory::SstiAndCodeInjection => TrapVerdict::SstiTemplateEval { confidence_pct },
        ViolationCategory::NoSqlInjection => TrapVerdict::NoSqlAdminDump { confidence_pct },
        ViolationCategory::XxeAndXmlInjection => TrapVerdict::XxeEntityLeak { confidence_pct },
        ViolationCategory::DeserializationAndPrototypePollution => {
            TrapVerdict::DeserializationJndiTrap { confidence_pct }
        }
        ViolationCategory::LdapInjection => TrapVerdict::LdapDirectoryDump { confidence_pct },
        ViolationCategory::Xss => TrapVerdict::XssBaitPage { confidence_pct },
        ViolationCategory::CrlfAndHeaderInjection => TrapVerdict::CrlfProxyDebug { confidence_pct },
        ViolationCategory::BufferOverflow => TrapVerdict::TarpitStream {
            kind: TarpitKind::GzipSqlBackup,
        },
        ViolationCategory::Custom(_) => TrapVerdict::ApiDebugEndpoint,
    };

    Some(verdict)
}

/// Extract a plausible shell command from a command-injection payload (e.g. `host=127.0.0.1;id` -> `id`,
/// `q=$(whoami)` -> `whoami`) so we can execute it safely inside `FakeShellSession`!
fn extract_injected_command(sample: &str) -> String {
    let decoded = percent_decode_lossy(sample);
    if let Some(start) = decoded.find("$(") {
        if let Some(end) = decoded[start + 2..].find(')') {
            let inner = decoded[start + 2..start + 2 + end].trim();
            if !inner.is_empty() {
                return inner.to_string();
            }
        }
    }
    if let Some(start) = decoded.find('`') {
        if let Some(end) = decoded[start + 1..].find('`') {
            let inner = decoded[start + 1..start + 1 + end].trim();
            if !inner.is_empty() {
                return inner.to_string();
            }
        }
    }
    for sep in [";", "&&", "|"] {
        if let Some((_, right)) = decoded.rsplit_once(sep) {
            let candidate = right.trim().replace("${IFS}", " ");
            if !candidate.is_empty() {
                return candidate;
            }
        }
    }
    "id".to_string()
}

fn detect_sqli(
    decoded_query: &str,
    query_upper: &str,
    cfg: &HttpHoneypotConfig,
    persona: &PrebakedPersona,
) -> Option<TrapVerdict> {
    if query_upper.contains("SLEEP(")
        || query_upper.contains("WAITFOR DELAY")
        || query_upper.contains("BENCHMARK(")
    {
        let extracted_secs = extract_number_after(query_upper, "SLEEP(")
            .unwrap_or((cfg.sqli_time_delay_ms / 1000).max(2))
            .clamp(1, 10);
        return Some(TrapVerdict::SqlInjectionTimeBlind {
            delay_ms: extracted_secs * 1000,
        });
    }

    if (query_upper.contains("SUBSTRING(")
        || query_upper.contains("MID(")
        || query_upper.contains("SUBSTR("))
        && (query_upper.contains("ASCII(") || query_upper.contains("ORD("))
    {
        let truthy = evaluate_sqlmap_char_probe(query_upper, &persona.db_secret_row);
        return Some(TrapVerdict::SqlInjectionBoolean { truthy });
    }

    if query_upper.contains(" AND ") || query_upper.contains(" OR ") {
        if query_upper.contains("1=1")
            || query_upper.contains("'A'='A")
            || query_upper.contains("'1'='1")
            || query_upper.contains("TRUE")
        {
            return Some(TrapVerdict::SqlInjectionBoolean { truthy: true });
        }
        if query_upper.contains("1=2")
            || query_upper.contains("1=0")
            || query_upper.contains("'A'='B")
            || query_upper.contains("'1'='2")
            || query_upper.contains("FALSE")
        {
            return Some(TrapVerdict::SqlInjectionBoolean { truthy: false });
        }
    }

    if query_upper.contains("UNION SELECT")
        || query_upper.contains("UNION ALL SELECT")
        || query_upper.contains("INFORMATION_SCHEMA")
        || query_upper.contains("EXTRACTVALUE(")
        || query_upper.contains("UPDATEXML(")
        || query_upper.contains("PG_CATALOG")
        || decoded_query.contains('\'')
        || decoded_query.contains("--")
    {
        let is_postgres = query_upper.contains("PG_") || (persona.slot_id % 2 == 1);
        return Some(TrapVerdict::SqlInjectionError { is_postgres });
    }

    None
}

fn evaluate_sqlmap_char_probe(query_upper: &str, secret_row: &str) -> bool {
    let pos_1based = extract_char_pos(query_upper).unwrap_or(1);
    let threshold = extract_number_after(query_upper, ">").unwrap_or(64) as u8;

    let secret_bytes = secret_row.as_bytes();
    if pos_1based == 0 || pos_1based > secret_bytes.len() {
        return false;
    }
    let actual_byte = secret_bytes[pos_1based - 1];
    actual_byte > threshold
}

fn extract_char_pos(s: &str) -> Option<usize> {
    for part in s.split(",1)") {
        if let Some(comma_idx) = part.rfind(',') {
            let candidate = part[comma_idx + 1..].trim();
            if let Ok(pos) = candidate.parse::<usize>() {
                return Some(pos);
            }
        }
    }
    None
}

fn extract_number_after(s: &str, marker: &str) -> Option<u64> {
    let idx = s.find(marker)?;
    let rest = s[idx + marker.len()..].trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<u64>().ok()
}

pub fn percent_decode_lossy(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
