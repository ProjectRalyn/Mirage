pub mod config;
pub mod db_traps;
pub mod detector;
pub mod engine;
pub mod persona;
pub mod shell;

pub use config::{
    AdminPanelConfig, HttpDeployMode, HttpHoneypotConfig, MirageConfig, PostgresHoneypotConfig,
    RedisHoneypotConfig, SigilFilterConfig, SinkFallbackTrap, SshDeployMode, SshHoneypotConfig,
};
pub use db_traps::{
    handle_postgres_connection, handle_redis_connection, run_standalone_postgres_server,
    run_standalone_redis_server, serve_postgres_listener, serve_redis_listener,
};
pub use detector::{classify_http_request, HttpRequestView, LfiTargetHint, TarpitKind, TrapVerdict};
pub use engine::{
    MirageEngine, MirageMetricsSnapshot, SshAuthDecision, TarpitPermit, ThreatEvent,
};
pub use persona::{
    PersonaSnapshot, PostgresPersonaData, PrebakedPersona, RedisPersonaData, SshVfsData,
};
pub use shell::{FakeShellSession, ShellExecResult};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn test_randomized_and_custom_admin_url_prefix() {
        let default_cfg = MirageConfig::default();
        let eng1 = MirageEngine::new(default_cfg.clone());
        let eng2 = MirageEngine::new(default_cfg);
        assert!(eng1.admin_path_prefix().starts_with("/_m_"));
        assert_eq!(eng1.admin_path_prefix().len(), 36);
        assert_ne!(eng1.admin_path_prefix(), eng2.admin_path_prefix());

        let mut custom_cfg = MirageConfig::default();
        custom_cfg.admin.path_prefix =
            "/__my_secret_ops_panel_9f8a7c2e1b4d603f5a1c8e9d2b7410a/".to_string();
        let eng_custom = MirageEngine::new(custom_cfg);
        assert_eq!(
            eng_custom.admin_path_prefix(),
            "/__my_secret_ops_panel_9f8a7c2e1b4d603f5a1c8e9d2b7410a"
        );
    }

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
        assert_eq!(p1.dotenv_body, p2.dotenv_body);

        let new_snap = engine.rotate_now();
        assert_eq!(new_snap.epoch_id, 2);

        let p1_after = engine.select_persona(ip1);
        assert_eq!(p1_after.epoch_id, 2);
        assert_ne!(p1.dotenv_body, p1_after.dotenv_body);
    }

    #[test]
    fn test_deep_wordpress_and_sqlmap_blind_extraction() {
        let cfg = MirageConfig::default();
        let engine = MirageEngine::new(cfg.clone());
        let ip: IpAddr = "198.51.100.42".parse().unwrap();
        let persona = engine.select_persona(ip);

        // 1. WordPress wp-config.php.bak backup leak
        let wp_bak = HttpRequestView {
            method: "GET",
            path: "/wp-config.php.bak",
            query: None,
            user_agent: None,
            header_samples: &[],
        };
        assert_eq!(
            classify_http_request(&wp_bak, &cfg.http, &cfg.sigil, engine.sigil(), &persona),
            TrapVerdict::WordPressConfigBackup
        );

        // 2. WordPress debug.log leak
        let wp_dbg = HttpRequestView {
            method: "GET",
            path: "/wp-content/debug.log",
            query: None,
            user_agent: None,
            header_samples: &[],
        };
        assert_eq!(
            classify_http_request(&wp_dbg, &cfg.http, &cfg.sigil, engine.sigil(), &persona),
            TrapVerdict::WordPressDebugLog
        );

        // 3. SQLMap Boolean-based blind character extraction
        let first_char = persona.db_secret_row.as_bytes()[0];
        let lower_threshold = first_char - 1;
        let higher_threshold = first_char;

        let sqli_true_query = format!(
            "id=1%20AND%20ORD(MID((SELECT%20password%20FROM%20users%20LIMIT%200,1),1,1))>{lower_threshold}"
        );
        let sqli_false_query = format!(
            "id=1%20AND%20ORD(MID((SELECT%20password%20FROM%20users%20LIMIT%200,1),1,1))>{higher_threshold}"
        );

        let req_true = HttpRequestView {
            method: "GET",
            path: "/api/v1/user",
            query: Some(&sqli_true_query),
            user_agent: Some("sqlmap/1.7"),
            header_samples: &[],
        };
        let req_false = HttpRequestView {
            method: "GET",
            path: "/api/v1/user",
            query: Some(&sqli_false_query),
            user_agent: Some("sqlmap/1.7"),
            header_samples: &[],
        };

        assert_eq!(
            classify_http_request(&req_true, &cfg.http, &cfg.sigil, engine.sigil(), &persona),
            TrapVerdict::SqlInjectionBoolean { truthy: true }
        );
        assert_eq!(
            classify_http_request(&req_false, &cfg.http, &cfg.sigil, engine.sigil(), &persona),
            TrapVerdict::SqlInjectionBoolean { truthy: false }
        );
    }

    #[test]
    fn test_sigil_filter_heuristic_detection_and_benign_passthrough() {
        let cfg = MirageConfig::default();
        let engine = MirageEngine::new(cfg.clone());
        let persona = engine.select_persona("203.0.113.55".parse().unwrap());

        // 1. Benign business request passes through cleanly
        let benign = HttpRequestView {
            method: "GET",
            path: "/api/v1/orders",
            query: Some("page=1&limit=20&sort=created_at"),
            user_agent: Some("Mozilla/5.0"),
            header_samples: &[("user-agent", "Mozilla/5.0")],
        };
        assert_eq!(
            classify_http_request(&benign, &cfg.http, &cfg.sigil, engine.sigil(), &persona),
            TrapVerdict::PassThrough
        );

        // 2. Double-encoded path traversal detected by sigil-filter -> PathTraversalLfi
        let lfi = HttpRequestView {
            method: "GET",
            path: "/download",
            query: Some("file=..%252f..%252f..%252fetc/passwd"),
            user_agent: Some("Mozilla/5.0"),
            header_samples: &[],
        };
        assert!(matches!(
            classify_http_request(&lfi, &cfg.http, &cfg.sigil, engine.sigil(), &persona),
            TrapVerdict::PathTraversalLfi {
                target: LfiTargetHint::EtcPasswd,
                ..
            }
        ));

        // 3. Cloud metadata SSRF detected by sigil-filter -> SsrfCloudMetadata
        let ssrf = HttpRequestView {
            method: "GET",
            path: "/api/v1/fetch",
            query: Some("url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
            user_agent: Some("Mozilla/5.0"),
            header_samples: &[],
        };
        assert!(matches!(
            classify_http_request(&ssrf, &cfg.http, &cfg.sigil, engine.sigil(), &persona),
            TrapVerdict::SsrfCloudMetadata { .. }
        ));

        // 4. Template injection detected by sigil-filter -> SstiTemplateEval
        let ssti = HttpRequestView {
            method: "GET",
            path: "/search",
            query: Some("q={{7*7}}"),
            user_agent: Some("Mozilla/5.0"),
            header_samples: &[],
        };
        assert!(matches!(
            classify_http_request(&ssti, &cfg.http, &cfg.sigil, engine.sigil(), &persona),
            TrapVerdict::SstiTemplateEval { .. }
        ));
    }

    #[test]
    fn test_full_linux_fake_shell_pipes_cow_and_tools() {
        let cfg = MirageConfig::default();
        let engine = MirageEngine::new(cfg);
        let persona = engine.select_persona("192.0.2.99".parse().unwrap());

        let mut shell = FakeShellSession::new(persona.clone(), None);

        // 1. Test pipeline (`cat /etc/passwd | grep bash | wc -l`)
        let pipe_res = shell.execute_line("cat /etc/passwd | grep bash");
        assert!(pipe_res.output.contains("root:x:0:0"));
        assert!(pipe_res.output.contains(&persona.ssh_vfs.default_user));
        assert!(!pipe_res.output.contains("nologin"));

        // 2. Test Copy-on-Write file redirection (`echo "ssh-ed25519 AAAA_ATTACKER" >> ~/.ssh/authorized_keys`)
        let redir_res =
            shell.execute_line("echo \"ssh-ed25519 AAAA_ATTACKER_KEY\" >> ~/.ssh/authorized_keys");
        assert!(redir_res
            .captured_indicators
            .iter()
            .any(|i| i.starts_with("file_write:")));

        let read_back = shell.execute_line("cat ~/.ssh/authorized_keys");
        assert!(read_back.output.contains("AAAA_ATTACKER_KEY"));

        // 3. Test realistic server tools (`sudo -l`, `docker ps`, `kubectl get secrets`, `redis-cli`, `psql`)
        let tools_res =
            shell.execute_line("sudo -l; docker ps; kubectl get secrets; redis-cli KEYS *; psql -c 'SELECT * FROM vault_secrets'");
        assert!(tools_res.output.contains("NOPASSWD: /usr/bin/python3 /opt/deploy/sync_vault.py"));
        assert!(tools_res.output.contains("nvcr.io/nvidia/pytorch"));
        assert!(tools_res.output.contains("postgres-superuser-secret"));
        assert!(tools_res.output.contains("vault:aws_credentials"));
        assert!(tools_res.output.contains("aws_root_s3_key"));
    }

    #[tokio::test]
    async fn test_redis_and_postgres_protocol_honeypots() {
        let mut cfg = MirageConfig::default();
        cfg.redis.auth_fail_delay_ms = 5;
        cfg.postgres.auth_fail_delay_ms = 5;
        let engine = MirageEngine::new(cfg);
        let persona = engine.select_persona("127.0.0.1".parse().unwrap());

        // 1. Test Redis RESP Honeypot using stolen password from persona
        let redis_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redis_addr = redis_listener.local_addr().unwrap();
        let eng_redis = engine.clone();
        tokio::spawn(async move {
            let _ = serve_redis_listener(redis_listener, eng_redis).await;
        });

        let mut r_client = TcpStream::connect(redis_addr).await.unwrap();
        let auth_cmd = format!("AUTH {}\r\n", persona.redis_data.require_pass);
        r_client.write_all(auth_cmd.as_bytes()).await.unwrap();
        let mut buf = [0u8; 512];
        let n = r_client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"+OK\r\n");

        r_client
            .write_all(b"GET vault:aws_credentials\r\n")
            .await
            .unwrap();
        let n = r_client.read(&mut buf).await.unwrap();
        let resp_str = String::from_utf8_lossy(&buf[..n]);
        assert!(resp_str.contains("AKIA"));

        // 2. Test PostgreSQL PGWire v3 Honeypot + CVE-2019-9193 COPY FROM PROGRAM RCE Trap
        let pg_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pg_addr = pg_listener.local_addr().unwrap();
        let eng_pg = engine.clone();
        tokio::spawn(async move {
            let _ = serve_postgres_listener(pg_listener, eng_pg).await;
        });

        let mut pg_client = TcpStream::connect(pg_addr).await.unwrap();
        // Send PG StartupMessage (version 3.0 = 196608)
        let mut startup = Vec::new();
        startup.extend_from_slice(&196608u32.to_be_bytes());
        startup.extend_from_slice(b"user\0postgres\0database\0prod_core_ledger\0\0");
        let total_len = (4 + startup.len()) as u32;
        pg_client.write_all(&total_len.to_be_bytes()).await.unwrap();
        pg_client.write_all(&startup).await.unwrap();

        // Read AuthenticationCleartextPassword ('R', len=8, 3)
        let mut auth_req = [0u8; 9];
        pg_client.read_exact(&mut auth_req).await.unwrap();
        assert_eq!(auth_req[0], b'R');

        // Send PasswordMessage ('p') with stolen PG password from persona
        let pass_bytes = format!("{}\0", persona.postgres_data.db_password).into_bytes();
        pg_client.write_all(b"p").await.unwrap();
        pg_client
            .write_all(&((4 + pass_bytes.len()) as u32).to_be_bytes())
            .await
            .unwrap();
        pg_client.write_all(&pass_bytes).await.unwrap();

        // Read handshake response containing AuthenticationOk + ReadyForQuery ('Z')
        let n = pg_client.read(&mut buf).await.unwrap();
        assert!(n > 20);
        assert_eq!(buf[0], b'R');

        // Send CVE-2019-9193 RCE query: COPY cmd_out FROM PROGRAM 'id; hostname'
        let sql = b"COPY cmd_out FROM PROGRAM 'id; hostname';\0";
        pg_client.write_all(b"Q").await.unwrap();
        pg_client
            .write_all(&((4 + sql.len()) as u32).to_be_bytes())
            .await
            .unwrap();
        pg_client.write_all(sql).await.unwrap();

        let n = pg_client.read(&mut buf).await.unwrap();
        let query_resp = String::from_utf8_lossy(&buf[..n]);
        assert!(query_resp.contains("uid=1000(postgres)"));
        assert!(query_resp.contains(&persona.hostname));
    }
}
