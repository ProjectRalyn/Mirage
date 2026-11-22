use crate::engine::MirageEngine;
use crate::shell::FakeShellSession;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::info;

// ============================================================================
// 1. Redis (RESP2 / RESP3) Deception & RCE Trap Engine
// ============================================================================

pub async fn run_standalone_redis_server(engine: Arc<MirageEngine>) -> io::Result<()> {
    if !engine.config().redis.enabled {
        return Ok(());
    }
    let bind_addr = engine.config().redis.bind_addr;
    let listener = TcpListener::bind(bind_addr).await?;
    info!(%bind_addr, "Mirage Redis (RESP) honeypot listening");
    serve_redis_listener(listener, engine).await
}

pub async fn serve_redis_listener(
    listener: TcpListener,
    engine: Arc<MirageEngine>,
) -> io::Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let eng = engine.clone();
        tokio::spawn(async move {
            let _ = handle_redis_connection(stream, peer_addr, eng).await;
        });
    }
}

pub async fn handle_redis_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    engine: Arc<MirageEngine>,
) -> io::Result<()> {
    let client_ip = peer_addr.ip();
    let persona = engine.select_persona(client_ip);
    let cfg = &engine.config().redis;

    let mut authenticated = cfg.accept_auth_on_attempt == 0;
    let mut auth_attempts = 0u32;
    let mut cow_dir = "/var/lib/redis".to_string();
    let mut cow_dbfilename = "dump.rdb".to_string();
    let mut cow_kv: HashMap<String, String> = HashMap::new();

    let mut buf = vec![0u8; 4096];

    loop {
        let n = match tokio::time::timeout(Duration::from_secs(60), stream.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => return Ok(()),
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
        };

        let args = parse_resp_command(&buf[..n]);
        if args.is_empty() {
            continue;
        }

        let cmd = args[0].to_ascii_uppercase();

        if cmd == "QUIT" {
            stream.write_all(b"+OK\r\n").await?;
            return Ok(());
        }

        if cmd == "AUTH" {
            auth_attempts += 1;
            let provided_pass = args.last().map(|s| s.as_str()).unwrap_or("");
            let matches_leaked_pass = provided_pass == persona.redis_data.require_pass;

            if matches_leaked_pass
                || (cfg.accept_auth_on_attempt > 0 && auth_attempts >= cfg.accept_auth_on_attempt)
            {
                authenticated = true;
                let trap_name = if matches_leaked_pass {
                    "RedisStolenCredentialUsed"
                } else {
                    "RedisBruteForceAccepted"
                };
                engine.record_event(
                    client_ip,
                    &persona,
                    "REDIS",
                    trap_name,
                    format!("AUTH accepted on attempt #{auth_attempts} (pass='{provided_pass}')"),
                );
                stream.write_all(b"+OK\r\n").await?;
            } else {
                engine.record_event(
                    client_ip,
                    &persona,
                    "REDIS",
                    "RedisAuthRejected",
                    format!("AUTH rejected attempt #{auth_attempts} (pass='{provided_pass}')"),
                );
                if cfg.auth_fail_delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(cfg.auth_fail_delay_ms)).await;
                }
                stream
                    .write_all(b"-WRONGPASS invalid username-password pair or user is disabled.\r\n")
                    .await?;
            }
            continue;
        }

        if !authenticated && cmd != "PING" && cmd != "COMMAND" && cmd != "HELLO" {
            stream
                .write_all(
                    b"-NOAUTH Authentication required. (Hint: see cluster wp-config / .env)\r\n",
                )
                .await?;
            continue;
        }

        match cmd.as_str() {
            "PING" => {
                stream.write_all(b"+PONG\r\n").await?;
            }
            "COMMAND" | "DOCS" => {
                stream.write_all(b"*0\r\n").await?;
            }
            "INFO" => {
                engine.record_event(client_ip, &persona, "REDIS", "InfoRecon", "INFO requested");
                stream.write_all(&persona.redis_data.info_resp_bulk).await?;
            }
            "DBSIZE" => {
                let total = persona.redis_data.kv_store.len() + cow_kv.len();
                stream
                    .write_all(format!(":{total}\r\n").as_bytes())
                    .await?;
            }
            "ROLE" => {
                stream
                    .write_all(b"*3\r\n$6\r\nmaster\r\n:894120412\r\n*0\r\n")
                    .await?;
            }
            "KEYS" => {
                engine.record_event(
                    client_ip,
                    &persona,
                    "REDIS",
                    "KeysEnumeration",
                    format!("KEYS {:?}", args.get(1).unwrap_or(&"*".to_string())),
                );
                let mut all_keys: Vec<&str> = persona
                    .redis_data
                    .kv_store
                    .keys()
                    .chain(cow_kv.keys())
                    .map(|k| k.as_str())
                    .collect();
                all_keys.sort();
                all_keys.dedup();
                let mut resp = format!("*{}\r\n", all_keys.len());
                for k in all_keys {
                    resp.push_str(&format!("${}\r\n{}\r\n", k.len(), k));
                }
                stream.write_all(resp.as_bytes()).await?;
            }
            "GET" => {
                let key = args.get(1).map(|s| s.as_str()).unwrap_or("");
                engine.record_event(
                    client_ip,
                    &persona,
                    "REDIS",
                    "SecretKeyRead",
                    format!("GET {key}"),
                );
                let val = cow_kv
                    .get(key)
                    .or_else(|| persona.redis_data.kv_store.get(key));
                match val {
                    Some(v) => {
                        stream
                            .write_all(format!("${}\r\n{}\r\n", v.len(), v).as_bytes())
                            .await?;
                    }
                    None => {
                        stream.write_all(b"$-1\r\n").await?;
                    }
                }
            }
            "SET" | "SETEX" | "PSETEX" => {
                let key = args.get(1).cloned().unwrap_or_default();
                let val = args.last().cloned().unwrap_or_default();
                engine.record_event(
                    client_ip,
                    &persona,
                    "REDIS",
                    "PayloadKeyWrite",
                    format!("SET key='{key}' val='{val}'"),
                );
                if cow_kv.len() < 16 && val.len() <= 2048 {
                    cow_kv.insert(key, val);
                }
                stream.write_all(b"+OK\r\n").await?;
            }
            "CONFIG" => {
                let sub = args
                    .get(1)
                    .map(|s| s.to_ascii_uppercase())
                    .unwrap_or_default();
                if sub == "GET" {
                    let param = args
                        .get(2)
                        .map(|s| s.to_ascii_lowercase())
                        .unwrap_or_default();
                    let resp = if param.contains("dir") {
                        format!("*2\r\n$3\r\ndir\r\n${}\r\n{}\r\n", cow_dir.len(), cow_dir)
                    } else if param.contains("dbfilename") {
                        format!(
                            "*2\r\n$10\r\ndbfilename\r\n${}\r\n{}\r\n",
                            cow_dbfilename.len(),
                            cow_dbfilename
                        )
                    } else {
                        format!(
                            "*4\r\n$3\r\ndir\r\n${}\r\n{}\r\n$10\r\ndbfilename\r\n${}\r\n{}\r\n",
                            cow_dir.len(),
                            cow_dir,
                            cow_dbfilename.len(),
                            cow_dbfilename
                        )
                    };
                    stream.write_all(resp.as_bytes()).await?;
                } else if sub == "SET" {
                    let param = args
                        .get(2)
                        .map(|s| s.to_ascii_lowercase())
                        .unwrap_or_default();
                    let val = args.get(3).cloned().unwrap_or_default();
                    if param == "dir" {
                        cow_dir = val.clone();
                    } else if param == "dbfilename" {
                        cow_dbfilename = val.clone();
                    }
                    engine.record_event(
                        client_ip,
                        &persona,
                        "REDIS",
                        "RedisCronOrSshRceTrap",
                        format!(
                            "CONFIG SET {param}='{val}' (current target: {cow_dir}/{cow_dbfilename})"
                        ),
                    );
                    stream.write_all(b"+OK\r\n").await?;
                } else {
                    stream.write_all(b"+OK\r\n").await?;
                }
            }
            "SAVE" | "BGSAVE" => {
                engine.record_event(
                    client_ip,
                    &persona,
                    "REDIS",
                    "RedisRdbExploitFlush",
                    format!("{cmd} triggered targeting {cow_dir}/{cow_dbfilename}"),
                );
                tokio::time::sleep(Duration::from_millis(1500)).await;
                stream.write_all(b"+OK\r\n").await?;
            }
            "SLAVEOF" | "REPLICAOF" => {
                let host = args.get(1).map(|s| s.as_str()).unwrap_or("unknown");
                let port = args.get(2).map(|s| s.as_str()).unwrap_or("unknown");
                engine.record_event(
                    client_ip,
                    &persona,
                    "REDIS",
                    "RedisRogueMasterRceTrap",
                    format!("{cmd} {host}:{port} rogue replication RCE attempt"),
                );
                tokio::time::sleep(Duration::from_millis(1800)).await;
                stream.write_all(b"+OK\r\n").await?;
            }
            "EVAL" | "EVALSHA" | "MODULE" => {
                engine.record_event(
                    client_ip,
                    &persona,
                    "REDIS",
                    "RedisLuaOrModuleExploit",
                    format!("{} {:?}", cmd, args),
                );
                stream.write_all(b"+OK\r\n").await?;
            }
            "SELECT" | "FLUSHALL" | "FLUSHDB" | "DEL" | "CLIENT" => {
                stream.write_all(b"+OK\r\n").await?;
            }
            _ => {
                stream
                    .write_all(format!("-ERR unknown command '{cmd}'\r\n").as_bytes())
                    .await?;
            }
        }
    }
}

/// Parse either a RESP multibulk array (`*N\r\n$len\r\narg\r\n...`) or an inline command string.
pub fn parse_resp_command(raw: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(raw);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if trimmed.starts_with('*') {
        let mut out = Vec::new();
        let mut lines = trimmed.lines();
        let _header = lines.next();
        while let Some(line) = lines.next() {
            if line.starts_with('$') {
                if let Some(val) = lines.next() {
                    out.push(val.to_string());
                }
            } else if !line.is_empty() {
                out.push(line.to_string());
            }
        }
        out
    } else {
        trimmed
            .split_whitespace()
            .map(|s| s.trim_matches('"').trim_matches('\'').to_string())
            .collect()
    }
}

// ============================================================================
// 2. PostgreSQL (PGWire v3.0) Deception & CVE-2019-9193 RCE Trap Engine
// ============================================================================

pub async fn run_standalone_postgres_server(engine: Arc<MirageEngine>) -> io::Result<()> {
    if !engine.config().postgres.enabled {
        return Ok(());
    }
    let bind_addr = engine.config().postgres.bind_addr;
    let listener = TcpListener::bind(bind_addr).await?;
    info!(%bind_addr, "Mirage PostgreSQL (PGWire v3) honeypot listening");
    serve_postgres_listener(listener, engine).await
}

pub async fn serve_postgres_listener(
    listener: TcpListener,
    engine: Arc<MirageEngine>,
) -> io::Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let eng = engine.clone();
        tokio::spawn(async move {
            let _ = handle_postgres_connection(stream, peer_addr, eng).await;
        });
    }
}

static PG_ATTEMPTS: std::sync::OnceLock<std::sync::Mutex<HashMap<IpAddr, u32>>> =
    std::sync::OnceLock::new();

pub async fn handle_postgres_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    engine: Arc<MirageEngine>,
) -> io::Result<()> {
    let client_ip = peer_addr.ip();
    let persona = engine.select_persona(client_ip);
    let cfg = &engine.config().postgres;

    // 1. Read Initial Startup Packet or SSLRequest
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let mut pkt_len = u32::from_be_bytes(len_buf) as usize;
    if !(8..=8192).contains(&pkt_len) {
        return Ok(());
    }
    let mut body = vec![0u8; pkt_len - 4];
    stream.read_exact(&mut body).await?;

    let code = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    // SSLRequest magic code = 80877103 (0x04d2162f)
    if code == 8087_7103 {
        // Decline SSL with 'N' so client sends standard v3 StartupMessage
        stream.write_all(b"N").await?;
        stream.flush().await?;
        stream.read_exact(&mut len_buf).await?;
        pkt_len = u32::from_be_bytes(len_buf) as usize;
        if !(8..=8192).contains(&pkt_len) {
            return Ok(());
        }
        body = vec![0u8; pkt_len - 4];
        stream.read_exact(&mut body).await?;
    }

    // Parse StartupMessage key-value pairs (user, database)
    let params_str = String::from_utf8_lossy(&body[4..]);
    let parts: Vec<&str> = params_str.split('\0').collect();
    let mut user = persona.postgres_data.db_user.clone();
    let mut i = 0;
    while i + 1 < parts.len() {
        if parts[i] == "user" && !parts[i + 1].is_empty() {
            user = parts[i + 1].to_string();
        }
        i += 2;
    }

    // 2. Request Cleartext Password ('R', len=8, auth_type=3)
    stream
        .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 3])
        .await?;
    stream.flush().await?;

    // 3. Read PasswordMessage ('p')
    let mut msg_type = [0u8; 1];
    stream.read_exact(&mut msg_type).await?;
    if msg_type[0] != b'p' {
        return Ok(());
    }
    stream.read_exact(&mut len_buf).await?;
    let pass_pkt_len = u32::from_be_bytes(len_buf) as usize;
    if !(4..=1024).contains(&pass_pkt_len) {
        return Ok(());
    }
    let mut pass_buf = vec![0u8; pass_pkt_len - 4];
    stream.read_exact(&mut pass_buf).await?;
    let password = String::from_utf8_lossy(&pass_buf)
        .trim_end_matches('\0')
        .to_string();

    let attempt = {
        let map_mutex = PG_ATTEMPTS.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
        let mut guard = map_mutex.lock().unwrap();
        if guard.len() > 4096 {
            guard.clear();
        }
        let e = guard.entry(client_ip).or_insert(0);
        *e += 1;
        *e
    };

    let matches_leaked_pass = password == persona.postgres_data.db_password;
    if !matches_leaked_pass
        && (cfg.accept_auth_on_attempt == 0 || attempt < cfg.accept_auth_on_attempt)
    {
        engine.record_event(
            client_ip,
            &persona,
            "POSTGRES",
            "PgAuthRejected",
            format!("Rejected PG login user='{user}' pass='{password}' (attempt #{attempt})"),
        );
        if cfg.auth_fail_delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(cfg.auth_fail_delay_ms)).await;
        }
        let err_msg = format!("password authentication failed for user \"{user}\"");
        send_pg_error(&mut stream, "28P01", &err_msg).await?;
        return Ok(());
    }

    engine.record_event(
        client_ip,
        &persona,
        "POSTGRES",
        if matches_leaked_pass {
            "PgStolenCredentialUsed"
        } else {
            "PgBruteForceAccepted"
        },
        format!("Accepted PG login user='{user}' pass='{password}' on attempt #{attempt}"),
    );

    // 4. Send AuthenticationOk + ParameterStatus + BackendKeyData + ReadyForQuery
    let mut handshake_out = Vec::with_capacity(256);
    // AuthenticationOk ('R', len=8, 0)
    handshake_out.extend_from_slice(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0]);
    append_pg_param_status(
        &mut handshake_out,
        "server_version",
        &persona.postgres_data.server_version_short,
    );
    append_pg_param_status(&mut handshake_out, "server_encoding", "UTF8");
    append_pg_param_status(&mut handshake_out, "client_encoding", "UTF8");
    append_pg_param_status(&mut handshake_out, "DateStyle", "ISO, MDY");
    append_pg_param_status(&mut handshake_out, "TimeZone", "UTC");
    append_pg_param_status(&mut handshake_out, "is_superuser", "on");
    // BackendKeyData ('K', len=12, pid=1190, key=0x4f1a9c21)
    handshake_out.extend_from_slice(&[b'K', 0, 0, 0, 12, 0, 0, 4, 166, 0x4f, 0x1a, 0x9c, 0x21]);
    // ReadyForQuery ('Z', len=5, 'I')
    handshake_out.extend_from_slice(&[b'Z', 0, 0, 0, 5, b'I']);
    stream.write_all(&handshake_out).await?;
    stream.flush().await?;

    // 5. Simple Query Loop ('Q')
    let mut shell = FakeShellSession::new(persona.clone(), Some("postgres"));
    loop {
        let n = match tokio::time::timeout(Duration::from_secs(60), stream.read(&mut msg_type))
            .await
        {
            Ok(Ok(0)) | Err(_) => return Ok(()),
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
        };
        if n == 0 || msg_type[0] == b'X' {
            return Ok(());
        }
        stream.read_exact(&mut len_buf).await?;
        let q_len = u32::from_be_bytes(len_buf) as usize;
        if !(4..=32768).contains(&q_len) {
            return Ok(());
        }
        let mut q_buf = vec![0u8; q_len - 4];
        stream.read_exact(&mut q_buf).await?;

        if msg_type[0] != b'Q' {
            stream.write_all(&[b'Z', 0, 0, 0, 5, b'I']).await?;
            continue;
        }

        let sql = String::from_utf8_lossy(&q_buf)
            .trim_end_matches('\0')
            .trim()
            .to_string();
        let sql_upper = sql.to_ascii_uppercase();

        engine.record_event(
            client_ip,
            &persona,
            "POSTGRES-SQL",
            "SqlQueryExecuted",
            format!("query: {sql}"),
        );

        // Check for CVE-2019-9193 `COPY ... FROM PROGRAM '...'` RCE exploit!
        if sql_upper.contains("FROM PROGRAM") {
            let cmd = extract_single_quoted(&sql).unwrap_or_else(|| "id".to_string());
            engine.record_event(
                client_ip,
                &persona,
                "POSTGRES-RCE",
                "CVE-2019-9193-CopyFromProgramTrap",
                format!("Captured COPY FROM PROGRAM command: {cmd}"),
            );
            let res = shell.execute_line(&cmd);
            if res.delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(res.delay_ms)).await;
            }
            let lines: Vec<Vec<String>> = res
                .output
                .lines()
                .map(|l| vec![l.to_string()])
                .collect();
            send_pg_result_set(
                &mut stream,
                &["cmd_output"],
                &lines,
                &format!("COPY {}", lines.len()),
            )
            .await?;
            continue;
        }

        if sql_upper.contains("VERSION()") {
            send_pg_result_set(
                &mut stream,
                &["version"],
                &[vec![persona.postgres_data.version_full_banner.clone()]],
                "SELECT 1",
            )
            .await?;
        } else if sql_upper.contains("VAULT_SECRETS") {
            let rows: Vec<Vec<String>> = persona
                .postgres_data
                .secrets_rows
                .iter()
                .map(|r| r.to_vec())
                .collect();
            send_pg_result_set(
                &mut stream,
                &["key_name", "secret_value", "canary_verify_url", "updated_at"],
                &rows,
                &format!("SELECT {}", rows.len()),
            )
            .await?;
        } else if sql_upper.contains("PG_TABLES") || sql_upper.contains("INFORMATION_SCHEMA.TABLES")
        {
            let rows = vec![
                vec![
                    "public".to_string(),
                    "users".to_string(),
                    persona.postgres_data.db_user.clone(),
                ],
                vec![
                    "public".to_string(),
                    "vault_secrets".to_string(),
                    persona.postgres_data.db_user.clone(),
                ],
                vec![
                    "public".to_string(),
                    "payment_settlements".to_string(),
                    persona.postgres_data.db_user.clone(),
                ],
            ];
            send_pg_result_set(&mut stream, &["schemaname", "tablename", "tableowner"], &rows, "SELECT 3")
                .await?;
        } else {
            let rows: Vec<Vec<String>> = persona
                .postgres_data
                .users_rows
                .iter()
                .map(|r| r.to_vec())
                .collect();
            send_pg_result_set(
                &mut stream,
                &["id", "username", "password_hash", "role", "api_token"],
                &rows,
                &format!("SELECT {}", rows.len()),
            )
            .await?;
        }
    }
}

fn append_pg_param_status(buf: &mut Vec<u8>, key: &str, val: &str) {
    let payload_len = 4 + key.len() + 1 + val.len() + 1;
    buf.push(b'S');
    buf.extend_from_slice(&(payload_len as u32).to_be_bytes());
    buf.extend_from_slice(key.as_bytes());
    buf.push(0);
    buf.extend_from_slice(val.as_bytes());
    buf.push(0);
}

async fn send_pg_error(stream: &mut TcpStream, code: &str, message: &str) -> io::Result<()> {
    let mut payload = Vec::new();
    payload.push(b'S');
    payload.extend_from_slice(b"FATAL\0");
    payload.push(b'C');
    payload.extend_from_slice(code.as_bytes());
    payload.push(0);
    payload.push(b'M');
    payload.extend_from_slice(message.as_bytes());
    payload.push(0);
    payload.push(0); // terminator

    let mut pkt = Vec::with_capacity(5 + payload.len());
    pkt.push(b'E');
    pkt.extend_from_slice(&((4 + payload.len()) as u32).to_be_bytes());
    pkt.extend_from_slice(&payload);
    stream.write_all(&pkt).await?;
    stream.flush().await
}

async fn send_pg_result_set(
    stream: &mut TcpStream,
    columns: &[&str],
    rows: &[Vec<String>],
    cmd_tag: &str,
) -> io::Result<()> {
    let mut out = Vec::with_capacity(512);

    // 1. RowDescription ('T')
    let mut row_desc = Vec::new();
    row_desc.extend_from_slice(&(columns.len() as u16).to_be_bytes());
    for col in columns {
        row_desc.extend_from_slice(col.as_bytes());
        row_desc.push(0);
        row_desc.extend_from_slice(&0u32.to_be_bytes()); // table OID
        row_desc.extend_from_slice(&0u16.to_be_bytes()); // attr num
        row_desc.extend_from_slice(&25u32.to_be_bytes()); // TEXT OID = 25
        row_desc.extend_from_slice(&(-1i16).to_be_bytes()); // type size
        row_desc.extend_from_slice(&(-1i32).to_be_bytes()); // type modifier
        row_desc.extend_from_slice(&0u16.to_be_bytes()); // text format = 0
    }
    out.push(b'T');
    out.extend_from_slice(&((4 + row_desc.len()) as u32).to_be_bytes());
    out.extend_from_slice(&row_desc);

    // 2. DataRows ('D')
    for row in rows {
        let mut data_row = Vec::new();
        data_row.extend_from_slice(&(row.len() as u16).to_be_bytes());
        for val in row {
            data_row.extend_from_slice(&(val.len() as u32).to_be_bytes());
            data_row.extend_from_slice(val.as_bytes());
        }
        out.push(b'D');
        out.extend_from_slice(&((4 + data_row.len()) as u32).to_be_bytes());
        out.extend_from_slice(&data_row);
    }

    // 3. CommandComplete ('C')
    let tag_len = 4 + cmd_tag.len() + 1;
    out.push(b'C');
    out.extend_from_slice(&(tag_len as u32).to_be_bytes());
    out.extend_from_slice(cmd_tag.as_bytes());
    out.push(0);

    // 4. ReadyForQuery ('Z', 'I')
    out.extend_from_slice(&[b'Z', 0, 0, 0, 5, b'I']);

    stream.write_all(&out).await?;
    stream.flush().await
}

fn extract_single_quoted(s: &str) -> Option<String> {
    let idx = s.to_ascii_uppercase().find("PROGRAM")?;
    let rest = &s[idx + 7..];
    let first_q = rest.find('\'')?;
    let after_first = &rest[first_q + 1..];
    let second_q = after_first.find('\'')?;
    Some(after_first[..second_q].to_string())
}
