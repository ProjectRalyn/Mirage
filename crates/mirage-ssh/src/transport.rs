use aes::Aes128;
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use mirage_core::{FakeShellSession, MirageEngine, PrebakedPersona, SshAuthDecision};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::io;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

type Aes128Ctr = Ctr128BE<Aes128>;
type HmacSha256 = Hmac<Sha256>;

const SSH_MSG_DISCONNECT: u8 = 1;
const SSH_MSG_IGNORE: u8 = 2;
const SSH_MSG_UNIMPLEMENTED: u8 = 3;
const SSH_MSG_SERVICE_REQUEST: u8 = 5;
const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
const SSH_MSG_KEXINIT: u8 = 20;
const SSH_MSG_NEWKEYS: u8 = 21;
const SSH_MSG_KEX_ECDH_INIT: u8 = 30;
const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;

const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
const SSH_MSG_USERAUTH_BANNER: u8 = 53;

const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
const SSH_MSG_REQUEST_FAILURE: u8 = 82;
const SSH_MSG_CHANNEL_OPEN: u8 = 90;
const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
const SSH_MSG_CHANNEL_DATA: u8 = 94;
const SSH_MSG_CHANNEL_EOF: u8 = 96;
const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
const SSH_MSG_CHANNEL_FAILURE: u8 = 100;

struct ActiveCipherState {
    c2s_cipher: Aes128Ctr,
    s2c_cipher: Aes128Ctr,
    c2s_mac_key: [u8; 32],
    s2c_mac_key: [u8; 32],
}

struct SshPacketCodec<S> {
    stream: S,
    c2s_seq: u32,
    s2c_seq: u32,
    cipher_state: Option<ActiveCipherState>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> SshPacketCodec<S> {
    fn new(stream: S) -> Self {
        Self {
            stream,
            c2s_seq: 0,
            s2c_seq: 0,
            cipher_state: None,
        }
    }

    async fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        if let Some(cs) = self.cipher_state.as_mut() {
            // Encrypted packet (aes128-ctr + hmac-sha2-256)
            let mut first_block = [0u8; 16];
            self.stream.read_exact(&mut first_block).await?;
            cs.c2s_cipher.apply_keystream(&mut first_block);

            let pkt_len = u32::from_be_bytes([
                first_block[0],
                first_block[1],
                first_block[2],
                first_block[3],
            ]) as usize;

            if !(5..=65536).contains(&pkt_len) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid encrypted SSH packet length: {pkt_len}"),
                ));
            }

            let total_len = 4 + pkt_len;
            if total_len < 16 || total_len % 16 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "encrypted SSH packet not aligned to 16-byte block",
                ));
            }

            let mut full_pkt = vec![0u8; total_len];
            full_pkt[..16].copy_from_slice(&first_block);
            if total_len > 16 {
                self.stream.read_exact(&mut full_pkt[16..]).await?;
                cs.c2s_cipher.apply_keystream(&mut full_pkt[16..]);
            }

            let mut received_mac = [0u8; 32];
            self.stream.read_exact(&mut received_mac).await?;

            // Verify HMAC-SHA2-256(seq || plaintext_packet)
            let mut mac =
                HmacSha256::new_from_slice(&cs.c2s_mac_key).expect("HMAC accepts 32-byte key");
            mac.update(&self.c2s_seq.to_be_bytes());
            mac.update(&full_pkt);
            mac.verify_slice(&received_mac)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SSH HMAC mismatch"))?;

            self.c2s_seq = self.c2s_seq.wrapping_add(1);

            let pad_len = full_pkt[4] as usize;
            if 1 + pad_len > pkt_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid SSH padding length",
                ));
            }
            let payload_end = 5 + (pkt_len - 1 - pad_len);
            Ok(full_pkt[5..payload_end].to_vec())
        } else {
            // Unencrypted packet
            let mut len_buf = [0u8; 4];
            self.stream.read_exact(&mut len_buf).await?;
            let pkt_len = u32::from_be_bytes(len_buf) as usize;
            if !(5..=65536).contains(&pkt_len) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid unencrypted SSH packet length: {pkt_len}"),
                ));
            }
            let mut body = vec![0u8; pkt_len];
            self.stream.read_exact(&mut body).await?;
            self.c2s_seq = self.c2s_seq.wrapping_add(1);

            let pad_len = body[0] as usize;
            if 1 + pad_len > pkt_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid SSH padding length",
                ));
            }
            let payload_len = pkt_len - 1 - pad_len;
            Ok(body[1..1 + payload_len].to_vec())
        }
    }

    async fn write_packet(&mut self, payload: &[u8]) -> io::Result<()> {
        let block_size = if self.cipher_state.is_some() { 16 } else { 8 };
        let unpadded_len = 4 + 1 + payload.len();
        let mut pad_len = block_size - (unpadded_len % block_size);
        if pad_len < 4 {
            pad_len += block_size;
        }
        let pkt_len = 1 + payload.len() + pad_len;

        let mut raw_pkt = Vec::with_capacity(4 + pkt_len + 32);
        raw_pkt.extend_from_slice(&(pkt_len as u32).to_be_bytes());
        raw_pkt.push(pad_len as u8);
        raw_pkt.extend_from_slice(payload);

        let mut pad_bytes = vec![0u8; pad_len];
        rand::thread_rng().fill_bytes(&mut pad_bytes);
        raw_pkt.extend_from_slice(&pad_bytes);

        if let Some(cs) = self.cipher_state.as_mut() {
            let mut mac =
                HmacSha256::new_from_slice(&cs.s2c_mac_key).expect("HMAC accepts 32-byte key");
            mac.update(&self.s2c_seq.to_be_bytes());
            mac.update(&raw_pkt);
            let tag = mac.finalize().into_bytes();

            cs.s2c_cipher.apply_keystream(&mut raw_pkt);
            raw_pkt.extend_from_slice(&tag);
        }

        self.s2c_seq = self.s2c_seq.wrapping_add(1);
        self.stream.write_all(&raw_pkt).await?;
        self.stream.flush().await
    }
}

/// Run a complete SSH-2 deception session over `stream` after the client identification banner
/// (`client_banner`, without trailing `\r\n`) has been read and the server banner has been sent.
pub async fn run_ssh2_deception_session<S>(
    stream: S,
    engine: Arc<MirageEngine>,
    persona: Arc<PrebakedPersona>,
    client_ip: IpAddr,
    client_banner: &str,
    server_banner: &str,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut codec = SshPacketCodec::new(stream);

    // 1. Send Server SSH_MSG_KEXINIT
    let server_kexinit = build_server_kexinit();
    codec.write_packet(&server_kexinit).await?;

    // 2. Read Client SSH_MSG_KEXINIT
    let client_kexinit = loop {
        let pkt = codec.read_packet().await?;
        if !pkt.is_empty() && pkt[0] == SSH_MSG_KEXINIT {
            break pkt;
        }
    };

    // 3. Read Client SSH_MSG_KEX_ECDH_INIT (opcode 30)
    let ecdh_init = loop {
        let pkt = codec.read_packet().await?;
        if !pkt.is_empty() && pkt[0] == SSH_MSG_KEX_ECDH_INIT {
            break pkt;
        }
    };

    let mut reader = SshReader::new(&ecdh_init[1..]);
    let q_c_bytes = reader.read_bytes()?;
    if q_c_bytes.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid client X25519 public key length",
        ));
    }
    let mut q_c_arr = [0u8; 32];
    q_c_arr.copy_from_slice(q_c_bytes);
    let q_c = X25519PublicKey::from(q_c_arr);

    // 4. Generate Server Ephemeral X25519 Keypair and compute Shared Secret K
    let mut server_ephemeral_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut server_ephemeral_bytes);
    let server_secret = X25519Secret::from(server_ephemeral_bytes);
    let q_s = X25519PublicKey::from(&server_secret);
    let shared_secret = server_secret.diffie_hellman(&q_c);

    // 5. Build Server Ed25519 Host Key blob K_S from the persona's rotating seed
    let host_signing_key = SigningKey::from_bytes(&persona.host_key_seed);
    let host_verifying_key = host_signing_key.verifying_key();
    let mut k_s = Vec::with_capacity(51);
    write_ssh_string(&mut k_s, b"ssh-ed25519");
    write_ssh_string(&mut k_s, host_verifying_key.as_bytes());

    // Encode shared secret K as SSH mpint
    let mut k_mpint = Vec::with_capacity(37);
    write_ssh_mpint(&mut k_mpint, shared_secret.as_bytes());

    // 6. Compute Exchange Hash H = SHA256(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)
    let mut hasher = Sha256::new();
    update_hash_ssh_string(&mut hasher, client_banner.as_bytes());
    update_hash_ssh_string(&mut hasher, server_banner.as_bytes());
    update_hash_ssh_string(&mut hasher, &client_kexinit);
    update_hash_ssh_string(&mut hasher, &server_kexinit);
    update_hash_ssh_string(&mut hasher, &k_s);
    update_hash_ssh_string(&mut hasher, q_c.as_bytes());
    update_hash_ssh_string(&mut hasher, q_s.as_bytes());
    hasher.update(&k_mpint);
    let exchange_hash_h: [u8; 32] = hasher.finalize().into();

    // 7. Sign Exchange Hash H with Ed25519 Host Key
    let sig = host_signing_key.sign(&exchange_hash_h);
    let mut sig_blob = Vec::with_capacity(83);
    write_ssh_string(&mut sig_blob, b"ssh-ed25519");
    write_ssh_string(&mut sig_blob, &sig.to_bytes());

    // 8. Send SSH_MSG_KEX_ECDH_REPLY (opcode 31) and SSH_MSG_NEWKEYS (opcode 21)
    let mut reply = Vec::with_capacity(200);
    reply.push(SSH_MSG_KEX_ECDH_REPLY);
    write_ssh_string(&mut reply, &k_s);
    write_ssh_string(&mut reply, q_s.as_bytes());
    write_ssh_string(&mut reply, &sig_blob);
    codec.write_packet(&reply).await?;
    codec.write_packet(&[SSH_MSG_NEWKEYS]).await?;

    // 9. Wait for Client SSH_MSG_NEWKEYS
    loop {
        let pkt = codec.read_packet().await?;
        if !pkt.is_empty() && pkt[0] == SSH_MSG_NEWKEYS {
            break;
        }
    }

    // 10. Derive RFC 4253 §7.2 Session Keys (session_id == exchange_hash_h for first KEX)
    let session_id = exchange_hash_h;
    let iv_c2s = derive_ssh_key(&k_mpint, &exchange_hash_h, b'A', &session_id);
    let iv_s2c = derive_ssh_key(&k_mpint, &exchange_hash_h, b'B', &session_id);
    let key_c2s = derive_ssh_key(&k_mpint, &exchange_hash_h, b'C', &session_id);
    let key_s2c = derive_ssh_key(&k_mpint, &exchange_hash_h, b'D', &session_id);
    let mac_c2s = derive_ssh_key(&k_mpint, &exchange_hash_h, b'E', &session_id);
    let mac_s2c = derive_ssh_key(&k_mpint, &exchange_hash_h, b'F', &session_id);

    let c2s_cipher = Aes128Ctr::new(key_c2s[..16].into(), iv_c2s[..16].into());
    let s2c_cipher = Aes128Ctr::new(key_s2c[..16].into(), iv_s2c[..16].into());

    codec.cipher_state = Some(ActiveCipherState {
        c2s_cipher,
        s2c_cipher,
        c2s_mac_key: mac_c2s,
        s2c_mac_key: mac_s2c,
    });

    // 11. Encrypted SSH-2 Authentication & Channel Loop
    let mut authenticated_user: Option<String> = None;
    let mut banner_sent = false;
    let mut shell_session: Option<FakeShellSession> = None;
    let mut client_channel_id: u32 = 0;
    let mut line_buffer = String::new();
    let mut esc_state: u8 = 0;
    let mut history_cursor: usize = 0;

    loop {
        let pkt = codec.read_packet().await?;
        if pkt.is_empty() {
            continue;
        }
        let msg_type = pkt[0];
        let mut r = SshReader::new(&pkt[1..]);

        match msg_type {
            SSH_MSG_DISCONNECT => return Ok(()),
            SSH_MSG_IGNORE | SSH_MSG_CHANNEL_WINDOW_ADJUST => {}
            SSH_MSG_SERVICE_REQUEST => {
                let service_name = r.read_string()?;
                let mut accept = Vec::with_capacity(1 + 4 + service_name.len());
                accept.push(SSH_MSG_SERVICE_ACCEPT);
                write_ssh_string(&mut accept, service_name.as_bytes());
                codec.write_packet(&accept).await?;
            }
            // CVE-2018-10933 libssh Authentication Bypass Trap!
            // If an attacker sends SSH_MSG_USERAUTH_SUCCESS (52) instead of USERAUTH_REQUEST (50):
            SSH_MSG_USERAUTH_SUCCESS if authenticated_user.is_none() => {
                engine.record_event(
                    client_ip,
                    &persona,
                    "SSH",
                    "CVE-2018-10933-AuthBypassTrap",
                    "Attacker sent client-side SSH_MSG_USERAUTH_SUCCESS exploit packet; granting fake shell access",
                );
                engine
                    .metrics
                    .ssh_fake_shell_logins
                    .fetch_add(1, Ordering::Relaxed);
                authenticated_user = Some(persona.ssh_vfs.default_user.clone());
            }
            SSH_MSG_USERAUTH_REQUEST => {
                let username = r.read_string()?;
                let _service = r.read_string()?;
                let method = r.read_string()?;

                if !banner_sent {
                    banner_sent = true;
                    let pre_auth_banner = format!(
                        "\r\n*** {} Production Cluster Node ({}) ***\r\n*** Notice: PAM hardware key daemon degraded; temporary password fallback active ***\r\n\r\n",
                        persona.hostname, persona.ssh_cve_profile
                    );
                    let mut b_pkt = Vec::new();
                    b_pkt.push(SSH_MSG_USERAUTH_BANNER);
                    write_ssh_string(&mut b_pkt, pre_auth_banner.as_bytes());
                    write_ssh_string(&mut b_pkt, b"en");
                    codec.write_packet(&b_pkt).await?;
                }

                match method.as_str() {
                    "password" => {
                        let _change_pass = r.read_u8()?;
                        let password = r.read_string()?;
                        match engine.evaluate_ssh_password_attempt(client_ip, &username, &password)
                        {
                            SshAuthDecision::AcceptIntoFakeShell { .. } => {
                                authenticated_user = Some(username);
                                codec.write_packet(&[SSH_MSG_USERAUTH_SUCCESS]).await?;
                            }
                            SshAuthDecision::RejectAfterDelay { delay_ms, .. } => {
                                if delay_ms > 0 {
                                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                }
                                let mut fail = Vec::new();
                                fail.push(SSH_MSG_USERAUTH_FAILURE);
                                write_ssh_string(&mut fail, b"password");
                                fail.push(0);
                                codec.write_packet(&fail).await?;
                            }
                        }
                    }
                    _ => {
                        // Reject 'none' or 'publickey' and advertise 'password' so client prompts for password
                        let mut fail = Vec::new();
                        fail.push(SSH_MSG_USERAUTH_FAILURE);
                        write_ssh_string(&mut fail, b"password");
                        fail.push(0);
                        codec.write_packet(&fail).await?;
                    }
                }
            }
            SSH_MSG_GLOBAL_REQUEST => {
                let _req_name = r.read_string()?;
                let want_reply = r.read_u8()? != 0;
                if want_reply {
                    codec.write_packet(&[SSH_MSG_REQUEST_FAILURE]).await?;
                }
            }
            SSH_MSG_CHANNEL_OPEN => {
                let _chan_type = r.read_string()?;
                let sender_channel = r.read_u32()?;
                let _initial_window = r.read_u32()?;
                let _max_pkt_size = r.read_u32()?;
                client_channel_id = sender_channel;

                let mut confirm = Vec::with_capacity(17);
                confirm.push(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
                confirm.extend_from_slice(&client_channel_id.to_be_bytes());
                confirm.extend_from_slice(&0u32.to_be_bytes()); // server channel id = 0
                confirm.extend_from_slice(&(2 * 1024 * 1024u32).to_be_bytes());
                confirm.extend_from_slice(&32768u32.to_be_bytes());
                codec.write_packet(&confirm).await?;
            }
            SSH_MSG_CHANNEL_REQUEST => {
                let _recipient_channel = r.read_u32()?;
                let req_type = r.read_string()?;
                let want_reply = r.read_u8()? != 0;

                match req_type.as_str() {
                    "pty-req" | "env" | "window-change" => {
                        if want_reply {
                            let mut ok = Vec::with_capacity(5);
                            ok.push(SSH_MSG_CHANNEL_SUCCESS);
                            ok.extend_from_slice(&client_channel_id.to_be_bytes());
                            codec.write_packet(&ok).await?;
                        }
                    }
                    "exec" => {
                        let cmd = r.read_string()?;
                        if want_reply {
                            let mut ok = Vec::with_capacity(5);
                            ok.push(SSH_MSG_CHANNEL_SUCCESS);
                            ok.extend_from_slice(&client_channel_id.to_be_bytes());
                            codec.write_packet(&ok).await?;
                        }

                        let mut session = FakeShellSession::new(
                            persona.clone(),
                            authenticated_user.as_deref(),
                        );
                        let exec_res = run_logged_shell_command(
                            &engine,
                            &persona,
                            client_ip,
                            &mut session,
                            &cmd,
                        )
                        .await;

                        if !exec_res.output.is_empty() {
                            send_channel_data(&mut codec, client_channel_id, exec_res.output.as_bytes()).await?;
                        }
                        send_channel_exit_and_close(&mut codec, client_channel_id).await?;
                        return Ok(());
                    }
                    "shell" => {
                        if want_reply {
                            let mut ok = Vec::with_capacity(5);
                            ok.push(SSH_MSG_CHANNEL_SUCCESS);
                            ok.extend_from_slice(&client_channel_id.to_be_bytes());
                            codec.write_packet(&ok).await?;
                        }

                        let session = FakeShellSession::new(
                            persona.clone(),
                            authenticated_user.as_deref(),
                        );
                        let welcome = format!("{}{}", session.welcome_banner(), session.prompt());
                        send_channel_data(&mut codec, client_channel_id, welcome.as_bytes())
                            .await?;
                        shell_session = Some(session);
                    }
                    _ => {
                        if want_reply {
                            let mut fail = Vec::with_capacity(5);
                            fail.push(SSH_MSG_CHANNEL_FAILURE);
                            fail.extend_from_slice(&client_channel_id.to_be_bytes());
                            codec.write_packet(&fail).await?;
                        }
                    }
                }
            }
            SSH_MSG_CHANNEL_DATA => {
                let _recipient_channel = r.read_u32()?;
                let data = r.read_bytes()?;

                let Some(session) = shell_session.as_mut() else {
                    continue;
                };

                for &byte in data {
                    // Handle ANSI escape sequences (e.g. Up/Down arrow keys `\x1b[A`, `\x1b[B`)
                    if esc_state == 1 {
                        if byte == b'[' {
                            esc_state = 2;
                        } else {
                            esc_state = 0;
                        }
                        continue;
                    } else if esc_state == 2 {
                        esc_state = 0;
                        let hist = session.history();
                        if !hist.is_empty() {
                            if byte == b'A' {
                                // Up arrow
                                history_cursor = history_cursor.saturating_add(1).min(hist.len());
                                line_buffer = hist[hist.len() - history_cursor].clone();
                                let redraw = format!("\r\x1b[K{}{}", session.prompt(), line_buffer);
                                send_channel_data(&mut codec, client_channel_id, redraw.as_bytes())
                                    .await?;
                            } else if byte == b'B' {
                                // Down arrow
                                history_cursor = history_cursor.saturating_sub(1);
                                line_buffer = if history_cursor == 0 {
                                    String::new()
                                } else {
                                    hist[hist.len() - history_cursor].clone()
                                };
                                let redraw = format!("\r\x1b[K{}{}", session.prompt(), line_buffer);
                                send_channel_data(&mut codec, client_channel_id, redraw.as_bytes())
                                    .await?;
                            }
                        }
                        continue;
                    }

                    match byte {
                        0x1b => {
                            esc_state = 1;
                        }
                        b'\t' => {
                            // Tab completion
                            if let Some(completion) = session.tab_complete(&line_buffer) {
                                line_buffer.push_str(&completion);
                                send_channel_data(
                                    &mut codec,
                                    client_channel_id,
                                    completion.as_bytes(),
                                )
                                .await?;
                            }
                        }
                        0x0c => {
                            // Ctrl-L (clear screen)
                            let redraw =
                                format!("\x1b[2J\x1b[H{}{}", session.prompt(), line_buffer);
                            send_channel_data(&mut codec, client_channel_id, redraw.as_bytes())
                                .await?;
                        }
                        0x15 => {
                            // Ctrl-U (clear line)
                            line_buffer.clear();
                            let redraw = format!("\r\x1b[K{}", session.prompt());
                            send_channel_data(&mut codec, client_channel_id, redraw.as_bytes())
                                .await?;
                        }
                        b'\r' | b'\n' => {
                            history_cursor = 0;
                            send_channel_data(&mut codec, client_channel_id, b"\r\n").await?;
                            let cmd_line = std::mem::take(&mut line_buffer);
                            let res = run_logged_shell_command(
                                &engine,
                                &persona,
                                client_ip,
                                session,
                                &cmd_line,
                            )
                            .await;

                            if !res.output.is_empty() {
                                let crlf_output = res.output.replace('\n', "\r\n");
                                send_channel_data(
                                    &mut codec,
                                    client_channel_id,
                                    crlf_output.as_bytes(),
                                )
                                .await?;
                            }

                            if res.should_exit {
                                send_channel_exit_and_close(&mut codec, client_channel_id).await?;
                                return Ok(());
                            }

                            let prompt = session.prompt();
                            send_channel_data(&mut codec, client_channel_id, prompt.as_bytes())
                                .await?;
                        }
                        0x03 => {
                            // Ctrl-C
                            history_cursor = 0;
                            line_buffer.clear();
                            let prompt = format!("^C\r\n{}", session.prompt());
                            send_channel_data(&mut codec, client_channel_id, prompt.as_bytes())
                                .await?;
                        }
                        0x04 => {
                            // Ctrl-D (EOF)
                            if line_buffer.is_empty() {
                                send_channel_data(&mut codec, client_channel_id, b"logout\r\n")
                                    .await?;
                                send_channel_exit_and_close(&mut codec, client_channel_id).await?;
                                return Ok(());
                            }
                        }
                        0x7f | 0x08 => {
                            // Backspace
                            if line_buffer.pop().is_some() {
                                send_channel_data(&mut codec, client_channel_id, b"\x08 \x08")
                                    .await?;
                            }
                        }
                        b if (0x20..=0x7e).contains(&b) => {
                            line_buffer.push(b as char);
                            send_channel_data(&mut codec, client_channel_id, &[b]).await?;
                        }
                        _ => {}
                    }
                }
            }
            SSH_MSG_CHANNEL_EOF | SSH_MSG_CHANNEL_CLOSE => {
                return Ok(());
            }
            _ => {
                let mut unimp = Vec::with_capacity(5);
                unimp.push(SSH_MSG_UNIMPLEMENTED);
                unimp.extend_from_slice(&codec.c2s_seq.wrapping_sub(1).to_be_bytes());
                codec.write_packet(&unimp).await?;
            }
        }
    }
}

async fn run_logged_shell_command(
    engine: &Arc<MirageEngine>,
    persona: &Arc<PrebakedPersona>,
    client_ip: IpAddr,
    session: &mut FakeShellSession,
    cmd_line: &str,
) -> mirage_core::ShellExecResult {
    let trimmed = cmd_line.trim();
    if !trimmed.is_empty() {
        engine
            .metrics
            .ssh_commands_executed
            .fetch_add(1, Ordering::Relaxed);
        engine.record_event(
            client_ip,
            persona,
            "SSH-SHELL",
            "AttackerCommand",
            format!("cmd: {trimmed}"),
        );
    }

    let res = session.execute_line(trimmed);

    for indicator in &res.captured_indicators {
        engine
            .metrics
            .malware_indicators_captured
            .fetch_add(1, Ordering::Relaxed);
        engine.record_event(
            client_ip,
            persona,
            "SSH-SHELL",
            "MalwarePayloadCaptured",
            format!("Captured payload indicator: {indicator}"),
        );
    }

    if res.delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(res.delay_ms)).await;
    }

    res
}

async fn send_channel_data<S: AsyncRead + AsyncWrite + Unpin>(
    codec: &mut SshPacketCodec<S>,
    recipient_channel: u32,
    data: &[u8],
) -> io::Result<()> {
    let mut pkt = Vec::with_capacity(9 + data.len());
    pkt.push(SSH_MSG_CHANNEL_DATA);
    pkt.extend_from_slice(&recipient_channel.to_be_bytes());
    write_ssh_string(&mut pkt, data);
    codec.write_packet(&pkt).await
}

async fn send_channel_exit_and_close<S: AsyncRead + AsyncWrite + Unpin>(
    codec: &mut SshPacketCodec<S>,
    recipient_channel: u32,
) -> io::Result<()> {
    // Send exit-status 0
    let mut status_pkt = Vec::with_capacity(28);
    status_pkt.push(SSH_MSG_CHANNEL_REQUEST);
    status_pkt.extend_from_slice(&recipient_channel.to_be_bytes());
    write_ssh_string(&mut status_pkt, b"exit-status");
    status_pkt.push(0); // want_reply = false
    status_pkt.extend_from_slice(&0u32.to_be_bytes());
    codec.write_packet(&status_pkt).await?;

    let mut eof = Vec::with_capacity(5);
    eof.push(SSH_MSG_CHANNEL_EOF);
    eof.extend_from_slice(&recipient_channel.to_be_bytes());
    codec.write_packet(&eof).await?;

    let mut close = Vec::with_capacity(5);
    close.push(SSH_MSG_CHANNEL_CLOSE);
    close.extend_from_slice(&recipient_channel.to_be_bytes());
    codec.write_packet(&close).await
}

fn build_server_kexinit() -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.push(SSH_MSG_KEXINIT);
    let mut cookie = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut cookie);
    buf.extend_from_slice(&cookie);

    // 10 algorithm name-lists
    write_ssh_string(&mut buf, b"curve25519-sha256,curve25519-sha256@libssh.org");
    write_ssh_string(&mut buf, b"ssh-ed25519");
    write_ssh_string(&mut buf, b"aes128-ctr");
    write_ssh_string(&mut buf, b"aes128-ctr");
    write_ssh_string(&mut buf, b"hmac-sha2-256");
    write_ssh_string(&mut buf, b"hmac-sha2-256");
    write_ssh_string(&mut buf, b"none");
    write_ssh_string(&mut buf, b"none");
    write_ssh_string(&mut buf, b"");
    write_ssh_string(&mut buf, b"");
    buf.push(0); // first_kex_packet_follows = false
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf
}

fn derive_ssh_key(
    k_mpint: &[u8],
    exchange_hash_h: &[u8; 32],
    letter: u8,
    session_id: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(k_mpint);
    hasher.update(exchange_hash_h);
    hasher.update([letter]);
    hasher.update(session_id);
    hasher.finalize().into()
}

fn write_ssh_string(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

fn update_hash_ssh_string(hasher: &mut Sha256, data: &[u8]) {
    hasher.update((data.len() as u32).to_be_bytes());
    hasher.update(data);
}

fn write_ssh_mpint(buf: &mut Vec<u8>, bytes: &[u8]) {
    let first_nonzero = bytes.iter().position(|&b| b != 0);
    let Some(idx) = first_nonzero else {
        buf.extend_from_slice(&0u32.to_be_bytes());
        return;
    };
    let trimmed = &bytes[idx..];
    if trimmed[0] & 0x80 != 0 {
        buf.extend_from_slice(&((trimmed.len() + 1) as u32).to_be_bytes());
        buf.push(0x00);
        buf.extend_from_slice(trimmed);
    } else {
        buf.extend_from_slice(&(trimmed.len() as u32).to_be_bytes());
        buf.extend_from_slice(trimmed);
    }
}

struct SshReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SshReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_u8(&mut self) -> io::Result<u8> {
        if self.pos >= self.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "SSH packet EOF reading u8",
            ));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_u32(&mut self) -> io::Result<u32> {
        if self.pos + 4 > self.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "SSH packet EOF reading u32",
            ));
        }
        let val = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(val)
    }

    fn read_bytes(&mut self) -> io::Result<&'a [u8]> {
        let len = self.read_u32()? as usize;
        if self.pos + len > self.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "SSH packet EOF reading string bytes",
            ));
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    fn read_string(&mut self) -> io::Result<String> {
        let bytes = self.read_bytes()?;
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }
}
