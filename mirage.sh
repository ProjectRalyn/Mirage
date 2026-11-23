#!/usr/bin/env bash
# Mirage Frontline OpenSSH Reverse Proxy & Pre-Auth CVE Shield Manager
# Repository: https://github.com/ProjectRalyn/Mirage
set -euo pipefail

REPO="ProjectRalyn/Mirage"
DAEMON_BIN="/usr/local/bin/mirage-daemon"
CONFIG_DIR="/etc/mirage"
CONFIG_FILE="${CONFIG_DIR}/config.toml"
SERVICE_FILE="/etc/systemd/system/mirage.service"
SSHD_CONFIG_FILE="/etc/ssh/sshd_config"
SSHD_CONFIG_BAK="/etc/ssh/sshd_config.mirage.bak"
SSHD_DROPIN_DIR="/etc/ssh/sshd_config.d"
SSHD_DROPIN_FILE="${SSHD_DROPIN_DIR}/99-mirage-upstream.conf"
SSH_SOCKET_MARKER="${CONFIG_DIR}/.ssh_socket_was_enabled"

if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' BOLD='' NC=''
fi

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()   { err "$*"; exit 1; }

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        die "Please run this script as root (e.g. sudo $0 $*)."
    fi
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Required command '$1' not found. Please install it first."
}

detect_arch() {
    local os arch
    os="$(uname -s)"
    [[ "$os" == "Linux" ]] || die "Unsupported OS: $os (Mirage release binaries target Linux)."
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)   echo "x86_64" ;;
        aarch64|arm64)  echo "aarch64" ;;
        *) die "Unsupported CPU architecture: $arch (supported: x86_64, aarch64)." ;;
    esac
}

detect_sshd_service() {
    if systemctl list-unit-files 2>/dev/null | grep -qE '^ssh\.service\b'; then
        echo "ssh"
    elif systemctl list-unit-files 2>/dev/null | grep -qE '^sshd\.service\b'; then
        echo "sshd"
    elif systemctl is-active --quiet ssh 2>/dev/null; then
        echo "ssh"
    elif systemctl is-active --quiet sshd 2>/dev/null; then
        echo "sshd"
    else
        echo ""
    fi
}

download_file() {
    local url="$1" dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
    else
        die "Neither curl nor wget is installed."
    fi
}

# Split host:port or [ipv6]:port -> prints "<host> <port>"
split_host_port() {
    local addr="$1"
    if [[ "$addr" =~ ^\[([^\]]+)\]:([0-9]+)$ ]]; then
        echo "${BASH_REMATCH[1]} ${BASH_REMATCH[2]}"
    elif [[ "$addr" =~ ^([^:]+):([0-9]+)$ ]]; then
        echo "${BASH_REMATCH[1]} ${BASH_REMATCH[2]}"
    else
        return 1
    fi
}

# Probe an SSH endpoint (host, port) to confirm it answers with an SSH- banner
probe_ssh_banner() {
    local host="$1" port="$2"
    [[ "$host" == "0.0.0.0" ]] && host="127.0.0.1"
    [[ "$host" == "::" ]] && host="::1"

    local attempt
    for attempt in 1 2 3 4 5; do
        if command -v python3 >/dev/null 2>&1; then
            if python3 - "$host" "$port" <<'PYEOF'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
try:
    with socket.create_connection((host, port), timeout=1.5) as s:
        s.settimeout(1.5)
        data = s.recv(64)
        sys.exit(0 if data.startswith(b"SSH-") else 1)
except Exception:
    sys.exit(1)
PYEOF
            then
                return 0
            fi
        elif command -v timeout >/dev/null 2>&1; then
            if timeout 2 bash -c "exec 3<>/dev/tcp/${host}/${port} && IFS= read -r -t 2 line <&3 && [[ \"\$line\" == SSH-* ]]" 2>/dev/null; then
                return 0
            fi
        else
            return 0
        fi
        sleep 0.5
    done
    return 1
}

get_toml_value() {
    local file="$1" section="$2" key="$3" default_val="${4:-}"
    if [[ ! -f "$file" ]] || ! command -v python3 >/dev/null 2>&1; then
        echo "$default_val"
        return
    fi
    python3 - "$file" "$section" "$key" "$default_val" <<'PYEOF'
import sys, re
path, section, key, default_val = sys.argv[1:5]
in_target = (section == "root")
sec_re = re.compile(r'^\s*\[([^\]]+)\]\s*$')
key_re = re.compile(rf'^\s*{re.escape(key)}\s*=\s*(.+?)\s*$')
with open(path, "r", encoding="utf-8") as f:
    for line in f:
        m_sec = sec_re.match(line)
        if m_sec:
            in_target = (m_sec.group(1).strip() == section)
            continue
        if in_target:
            m_k = key_re.match(line)
            if m_k:
                val = m_k.group(1).split('#', 1)[0].strip().strip('"').strip("'")
                print(val)
                sys.exit(0)
print(default_val)
PYEOF
}

set_toml_key_in_section() {
    local file="$1" section="$2" key="$3" val="$4"
    python3 - "$file" "$section" "$key" "$val" <<'PYEOF'
import sys, re

path, section, key, val = sys.argv[1:5]
with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

in_target = (section == "root")
key_re = re.compile(rf'^(\s*#?\s*){re.escape(key)}\s*=.*$')
sec_re = re.compile(r'^\s*\[([^\]]+)\]\s*$')

out = []
replaced = False
for line in lines:
    m_sec = sec_re.match(line)
    if m_sec:
        if in_target and not replaced:
            out.append(f"{key} = {val}\n")
            replaced = True
        in_target = (m_sec.group(1).strip() == section)
        out.append(line)
        continue

    if in_target and not replaced and key_re.match(line):
        out.append(f"{key} = {val}\n")
        replaced = True
    else:
        out.append(line)

if not replaced:
    if section != "root":
        out.append(f"\n[{section}]\n")
    out.append(f"{key} = {val}\n")

with open(path, "w", encoding="utf-8") as f:
    f.writelines(out)
PYEOF
}

update_toml_value() {
    local section="$1" key="$2" val="$3"
    if command -v python3 >/dev/null 2>&1; then
        set_toml_key_in_section "$CONFIG_FILE" "$section" "$key" "$val"
    else
        warn "python3 not found; please edit ${CONFIG_FILE} manually."
    fi
}

install_release() {
    local version="${1:-latest}"
    require_root
    require_cmd tar

    local arch archive_name base_url tmp_dir
    arch="$(detect_arch)"
    archive_name="mirage-linux-${arch}.tar.gz"

    if [[ "$version" == "latest" ]]; then
        base_url="https://github.com/${REPO}/releases/latest/download"
    else
        base_url="https://github.com/${REPO}/releases/download/${version}"
    fi

    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "$tmp_dir"' RETURN

    info "Downloading ${archive_name} (${version}) for ${arch}..."
    download_file "${base_url}/${archive_name}" "${tmp_dir}/${archive_name}" \
        || die "Failed to download ${base_url}/${archive_name}. Check network or release tag."

    if download_file "${base_url}/SHA256SUMS.txt" "${tmp_dir}/SHA256SUMS.txt" 2>/dev/null; then
        info "Verifying SHA256 checksum..."
        if command -v sha256sum >/dev/null 2>&1; then
            (cd "$tmp_dir" && grep " ${archive_name}\$" SHA256SUMS.txt | sha256sum -c -) \
                || die "SHA256 checksum verification failed!"
            ok "Checksum verified."
        else
            warn "sha256sum not found; skipping checksum verification."
        fi
    fi

    info "Extracting release archive..."
    tar -xzf "${tmp_dir}/${archive_name}" -C "$tmp_dir"

    install -d -m 0755 /usr/local/bin "$CONFIG_DIR"
    install -m 0755 "${tmp_dir}/mirage-daemon" "$DAEMON_BIN"

    if [[ ! -f "$CONFIG_FILE" ]]; then
        if [[ -f "${tmp_dir}/config.example.toml" ]]; then
            cp "${tmp_dir}/config.example.toml" "$CONFIG_FILE"
        else
            "$DAEMON_BIN" --print-default-config > "$CONFIG_FILE"
        fi
        chmod 0640 "$CONFIG_FILE"
        ok "Created default config at ${CONFIG_FILE}"
    else
        info "Existing config preserved at ${CONFIG_FILE}"
    fi

    ok "Installed binary: $DAEMON_BIN"

    if systemctl is-active --quiet mirage 2>/dev/null; then
        info "Restarting running mirage service..."
        systemctl restart mirage
        ok "Mirage service restarted."
    fi
}

write_systemd_service() {
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Mirage OpenSSH Frontline Reverse Proxy & Pre-Auth CVE Shield
After=network-online.target ssh.service sshd.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=${DAEMON_BIN} --config ${CONFIG_FILE}
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    ok "Systemd service written to ${SERVICE_FILE}"
}

restore_openssh_config() {
    require_root
    local ssh_svc
    ssh_svc="$(detect_sshd_service)"

    if systemctl is-active --quiet mirage 2>/dev/null; then
        info "Stopping mirage service to release public SSH port..."
        systemctl stop mirage 2>/dev/null || true
    fi

    if [[ -f "$SSHD_DROPIN_FILE" ]]; then
        rm -f "$SSHD_DROPIN_FILE"
        ok "Removed ${SSHD_DROPIN_FILE}"
    fi

    if [[ -f "$SSHD_CONFIG_BAK" ]]; then
        cp -p "$SSHD_CONFIG_BAK" "$SSHD_CONFIG_FILE"
        ok "Restored ${SSHD_CONFIG_FILE} from ${SSHD_CONFIG_BAK}"
    fi

    if command -v sshd >/dev/null 2>&1; then
        if ! sshd -t; then
            err "sshd -t failed after restore! Please inspect ${SSHD_CONFIG_FILE} before closing this session."
            return 1
        fi
    fi

    if [[ -f "$SSH_SOCKET_MARKER" ]]; then
        rm -f "$SSH_SOCKET_MARKER"
        info "Restoring systemd ssh.socket activation..."
        [[ -n "$ssh_svc" ]] && systemctl stop "${ssh_svc}.service" 2>/dev/null || true
        systemctl enable --now ssh.socket 2>/dev/null || true
        ok "Restored ssh.socket."
    elif [[ -n "$ssh_svc" ]]; then
        systemctl restart "$ssh_svc"
        ok "Restarted ${ssh_svc}.service with original OpenSSH configuration."
    else
        warn "Could not detect ssh/sshd systemd service; please restart sshd manually."
    fi
}

configure_openssh_upstream() {
    require_root
    local upstream_addr="${1:-}"
    if [[ -z "$upstream_addr" ]]; then
        upstream_addr="$(get_toml_value "$CONFIG_FILE" "ssh" "upstream_sshd_addr" "127.0.0.1:22022")"
        read -rp "Move local OpenSSH sshd to ListenAddress [${upstream_addr}]: " input_addr
        upstream_addr="${input_addr:-$upstream_addr}"
    fi

    local host port
    read -r host port < <(split_host_port "$upstream_addr") \
        || die "Invalid upstream_sshd_addr '${upstream_addr}' (expected host:port, e.g. 127.0.0.1:22022)."

    [[ -f "$SSHD_CONFIG_FILE" ]] || die "Missing ${SSHD_CONFIG_FILE}. Is OpenSSH server installed?"
    require_cmd sshd

    local ssh_svc
    ssh_svc="$(detect_sshd_service)"
    [[ -n "$ssh_svc" ]] || warn "Could not auto-detect ssh/sshd systemd service name."

    # Handle SELinux ssh_port_t if Enforcing (RHEL/Rocky/Alma/Fedora)
    if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce 2>/dev/null || true)" == "Enforcing" ]]; then
        if command -v semanage >/dev/null 2>&1; then
            info "SELinux Enforcing detected; permitting tcp/${port} for ssh_port_t..."
            semanage port -a -t ssh_port_t -p tcp "$port" 2>/dev/null \
                || semanage port -m -t ssh_port_t -p tcp "$port" 2>/dev/null \
                || warn "semanage failed to add tcp/${port}; sshd may fail to bind if SELinux blocks port ${port}."
        else
            warn "SELinux is Enforcing and 'semanage' is not installed; ensure port ${port} is allowed for ssh_port_t."
        fi
    fi

    install -d -m 0755 "$CONFIG_DIR" "$SSHD_DROPIN_DIR"

    # Backup original /etc/ssh/sshd_config once
    if [[ ! -f "$SSHD_CONFIG_BAK" ]]; then
        cp -p "$SSHD_CONFIG_FILE" "$SSHD_CONFIG_BAK"
        ok "Backed up ${SSHD_CONFIG_FILE} to ${SSHD_CONFIG_BAK}"
    fi

    # Ensure sshd_config includes /etc/ssh/sshd_config.d/*.conf and comment out conflicting ListenAddress lines
    if ! grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_CONFIG_FILE"; then
        local tmp_cfg
        tmp_cfg="$(mktemp)"
        {
            echo "Include /etc/ssh/sshd_config.d/*.conf"
            cat "$SSHD_CONFIG_FILE"
        } > "$tmp_cfg"
        cat "$tmp_cfg" > "$SSHD_CONFIG_FILE"
        rm -f "$tmp_cfg"
        ok "Added 'Include /etc/ssh/sshd_config.d/*.conf' to ${SSHD_CONFIG_FILE}"
    fi

    if grep -qE '^\s*ListenAddress\s+' "$SSHD_CONFIG_FILE"; then
        local tmp_cfg
        tmp_cfg="$(mktemp)"
        sed -E 's/^(\s*ListenAddress\s+.*)/# mirage-disabled: \1/' "$SSHD_CONFIG_FILE" > "$tmp_cfg"
        cat "$tmp_cfg" > "$SSHD_CONFIG_FILE"
        rm -f "$tmp_cfg"
        info "Commented out conflicting ListenAddress lines in ${SSHD_CONFIG_FILE} (backed up in ${SSHD_CONFIG_BAK})."
    fi

    # Write OpenSSH upstream drop-in
    cat > "$SSHD_DROPIN_FILE" <<EOF
# Managed by mirage.sh - Upstream OpenSSH backend behind Mirage Frontline Shield
ListenAddress ${upstream_addr}
EOF
    ok "Wrote ${SSHD_DROPIN_FILE} (ListenAddress ${upstream_addr})"

    # Validate sshd configuration before restarting
    if ! sshd -t; then
        err "sshd -t validation failed! Rolling back OpenSSH configuration..."
        restore_openssh_config || true
        die "Rollback complete. OpenSSH was NOT modified."
    fi
    ok "sshd -t validation passed."

    # Verify effective ListenAddress via sshd -T
    local effective_listen
    effective_listen="$(sshd -T 2>/dev/null | awk 'tolower($1)=="listenaddress"{print $2}' | tr '\n' ' ')"
    info "Effective OpenSSH ListenAddress: ${effective_listen:-unknown}"

    # Handle Ubuntu 22.10+/24.04 systemd ssh.socket activation (otherwise socket holds port 22!)
    if systemctl is-active --quiet ssh.socket 2>/dev/null || systemctl is-enabled --quiet ssh.socket 2>/dev/null; then
        info "Detected systemd ssh.socket activation; switching to ${ssh_svc:-ssh}.service so port 22 is released..."
        touch "$SSH_SOCKET_MARKER"
        systemctl disable --now ssh.socket 2>/dev/null || true
        if [[ -n "$ssh_svc" ]]; then
            systemctl enable "$ssh_svc" 2>/dev/null || true
        fi
    fi

    # Restart sshd to bind the new upstream loopback port (existing SSH sessions stay alive)
    if [[ -n "$ssh_svc" ]]; then
        if ! systemctl restart "$ssh_svc"; then
            err "Failed to restart ${ssh_svc}! Rolling back OpenSSH configuration..."
            restore_openssh_config || true
            die "Rollback complete."
        fi
    else
        die "Cannot restart sshd automatically (systemd unit not found). Rolling back..."
    fi

    # Verify upstream sshd is actually responding with an SSH banner on host:port
    info "Verifying upstream OpenSSH responds on ${upstream_addr}..."
    if ! probe_ssh_banner "$host" "$port"; then
        err "Upstream OpenSSH did NOT respond on ${upstream_addr}! Rolling back immediately to prevent lockout..."
        restore_openssh_config || true
        die "Rollback complete. OpenSSH has been restored to its original port."
    fi
    ok "Upstream OpenSSH is live and verified on ${upstream_addr}!"
}

deploy_wizard() {
    local skip_install="${1:-}"
    require_root
    if [[ "$skip_install" != "--skip-install" ]]; then
        if [[ ! -x "$DAEMON_BIN" ]]; then
            install_release
        else
            read -rp "Mirage is already installed. Update to latest release first? [y/N]: " ans
            if [[ "${ans,,}" == "y" ]]; then
                install_release
            fi
        fi
    fi

    echo
    echo -e "${BOLD}=== Mirage Frontline SSH Shield Deployment Wizard ===${NC}"
    echo "Press Enter to accept defaults in [brackets]."
    echo

    read -rp "Mirage public SSH listen address [0.0.0.0:22]: " ssh_addr
    ssh_addr="${ssh_addr:-0.0.0.0:22}"
    read -rp "Real upstream OpenSSH address [127.0.0.1:22022]: " upstream_ssh
    upstream_ssh="${upstream_ssh:-127.0.0.1:22022}"

    echo
    echo "Per-category response actions: 1) fail2ban  2) ssh_honeypot  3) endlessh_tarpit  4) drop"

    read -rp "Action on brute-force bursts [1=fail2ban]: " bf_choice
    local bf_action="fail2ban"
    case "${bf_choice:-1}" in
        1|fail2ban|ban)    bf_action="fail2ban" ;;
        2|ssh_honeypot)    bf_action="ssh_honeypot" ;;
        3|endlessh_tarpit) bf_action="endlessh_tarpit" ;;
        4|drop)            bf_action="drop" ;;
        *) warn "Invalid choice, using fail2ban." ;;
    esac

    read -rp "Action on pre-auth CVE / sigil violations [2=ssh_honeypot]: " cve_choice
    local cve_action="ssh_honeypot"
    case "${cve_choice:-2}" in
        1|fail2ban|ban)    cve_action="fail2ban" ;;
        2|ssh_honeypot)    cve_action="ssh_honeypot" ;;
        3|endlessh_tarpit) cve_action="endlessh_tarpit" ;;
        4|drop)            cve_action="drop" ;;
        *) warn "Invalid choice, using ssh_honeypot." ;;
    esac

    read -rp "Action on scanner banners [3=endlessh_tarpit]: " sc_choice
    local sc_action="endlessh_tarpit"
    case "${sc_choice:-3}" in
        1|fail2ban|ban)    sc_action="fail2ban" ;;
        2|ssh_honeypot)    sc_action="ssh_honeypot" ;;
        3|endlessh_tarpit) sc_action="endlessh_tarpit" ;;
        4|drop)            sc_action="drop" ;;
        *) warn "Invalid choice, using endlessh_tarpit." ;;
    esac

    if [[ "$bf_action" == "fail2ban" || "$cve_action" == "fail2ban" || "$sc_action" == "fail2ban" ]]; then
        read -rp "Optional MIRAGE_BAN log file for host Fail2Ban/nftables (e.g. /var/log/mirage-bans.log, Enter to skip): " ban_log
        if [[ -n "$ban_log" ]]; then
            update_toml_value "ssh" "ban_log_file" "\"${ban_log}\""
        fi
    fi

    update_toml_value "ssh" "bind_addr" "\"${ssh_addr}\""
    update_toml_value "ssh" "upstream_sshd_addr" "\"${upstream_ssh}\""
    update_toml_value "ssh" "bruteforce_action" "\"${bf_action}\""
    update_toml_value "ssh" "cve_exploit_action" "\"${cve_action}\""
    update_toml_value "ssh" "scanner_action" "\"${sc_action}\""
    update_toml_value "ssh" "honeypot_log_file" "\"/var/log/mirage-honeypot.jsonl\""

    # Optionally reconfigure local OpenSSH automatically BEFORE starting Mirage on port 22
    echo
    local auto_sshd="n"
    local ssh_host ssh_port
    read -r ssh_host ssh_port < <(split_host_port "$ssh_addr") || ssh_port=""
    if [[ "$ssh_port" == "22" ]]; then
        read -rp "Automatically move local OpenSSH sshd to ${upstream_ssh} so Mirage can take port 22? (with auto-rollback on error) [Y/n]: " ans
        [[ "${ans,,}" != "n" ]] && auto_sshd="y"
    else
        read -rp "Automatically configure local OpenSSH sshd to listen on ${upstream_ssh}? [y/N]: " ans
        [[ "${ans,,}" == "y" ]] && auto_sshd="y"
    fi

    if [[ "$auto_sshd" == "y" ]]; then
        configure_openssh_upstream "$upstream_ssh"
    fi

    write_systemd_service
    systemctl enable mirage >/dev/null 2>&1 || true
    if ! systemctl restart mirage; then
        err "Mirage failed to start!"
        if [[ "$auto_sshd" == "y" ]]; then
            warn "Rolling back OpenSSH automatically to prevent lockout..."
            restore_openssh_config || true
        fi
        journalctl -u mirage -n 30 --no-pager || true
        die "Deployment aborted."
    fi

    # End-to-end verification: confirm Mirage is answering SSH on bind_addr
    if [[ -n "${ssh_host:-}" && -n "${ssh_port:-}" ]]; then
        info "Verifying Mirage Frontline SSH Shield responds on ${ssh_addr}..."
        if ! probe_ssh_banner "$ssh_host" "$ssh_port"; then
            err "Mirage did NOT respond with an SSH banner on ${ssh_addr}!"
            if [[ "$auto_sshd" == "y" ]]; then
                warn "Rolling back OpenSSH automatically to prevent lockout..."
                restore_openssh_config || true
            fi
            journalctl -u mirage -n 30 --no-pager || true
            die "Deployment aborted; OpenSSH restored."
        fi
    fi

    echo
    ok "Mirage Frontline SSH Shield is LIVE on ${ssh_addr} -> ${upstream_ssh}!"
    if [[ "$auto_sshd" == "y" ]]; then
        warn "IMPORTANT: Keep this SSH session open and verify logging in from a NEW terminal before closing!"
    else
        echo
        "$DAEMON_BIN" --config "$CONFIG_FILE" --print-sshd-config
    fi
}

edit_config() {
    require_root
    [[ -f "$CONFIG_FILE" ]] || die "Config file not found at ${CONFIG_FILE}. Run '$0 deploy' or '$0 install' first."

    echo
    echo -e "${BOLD}=== Edit Mirage Configuration ===${NC}"
    echo "1) Open ${CONFIG_FILE} in editor (${EDITOR:-nano/vi})"
    echo "2) Print upstream OpenSSH sshd & Fail2Ban setup guide"
    echo "0) Back"
    read -rp "Choose [1]: " choice
    case "${choice:-1}" in
        1)
            local ed="${EDITOR:-}"
            if [[ -z "$ed" ]]; then
                if command -v nano >/dev/null 2>&1; then ed="nano"
                elif command -v vim >/dev/null 2>&1; then ed="vim"
                else ed="vi"
                fi
            fi
            "$ed" "$CONFIG_FILE"
            if systemctl is-active --quiet mirage 2>/dev/null; then
                read -rp "Restart mirage service to apply changes? [Y/n]: " r
                [[ "${r,,}" != "n" ]] && systemctl restart mirage && ok "Mirage restarted."
            fi
            ;;
        2) "$DAEMON_BIN" --config "$CONFIG_FILE" --print-sshd-config ;;
        0) return 0 ;;
        *) warn "Invalid option." ;;
    esac
}

show_logs() {
    journalctl -u mirage -n 50 -f
}

uninstall_mirage() {
    require_root
    echo -e "${YELLOW}This will stop Mirage, restore OpenSSH (if modified), and remove Mirage binaries/systemd unit.${NC}"
    read -rp "Continue? [y/N]: " confirm
    [[ "${confirm,,}" == "y" ]] || { info "Cancelled."; return 0; }

    if systemctl list-unit-files | grep -q "^mirage\.service"; then
        systemctl stop mirage 2>/dev/null || true
        systemctl disable mirage 2>/dev/null || true
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
        ok "Removed systemd service."
    fi

    if [[ -f "$SSHD_DROPIN_FILE" || -f "$SSHD_CONFIG_BAK" || -f "$SSH_SOCKET_MARKER" ]]; then
        info "Restoring original OpenSSH configuration..."
        restore_openssh_config || warn "Please verify OpenSSH status manually."
    fi

    rm -f "$DAEMON_BIN"
    ok "Removed ${DAEMON_BIN}."

    read -rp "Also remove config directory ${CONFIG_DIR} and ${SSHD_CONFIG_BAK}? [y/N]: " rm_cfg
    if [[ "${rm_cfg,,}" == "y" ]]; then
        rm -rf "$CONFIG_DIR" "$SSHD_CONFIG_BAK"
        ok "Removed configuration."
    fi
}

show_status() {
    echo -e "${BOLD}=== Mirage Status ===${NC}"
    [[ -x "$DAEMON_BIN" ]] && ok "Binary: $DAEMON_BIN" || warn "Binary not installed"
    [[ -f "$CONFIG_FILE" ]] && ok "Config: $CONFIG_FILE" || warn "Config not found"
    if [[ -f "$SSHD_DROPIN_FILE" ]]; then
        ok "OpenSSH upstream drop-in active: $SSHD_DROPIN_FILE ($(grep -i '^ListenAddress' "$SSHD_DROPIN_FILE" || true))"
    else
        info "OpenSSH upstream drop-in not configured (${SSHD_DROPIN_FILE})"
    fi
    if systemctl list-unit-files | grep -q "^mirage\.service"; then
        systemctl --no-pager -l status mirage || true
    else
        warn "Systemd service not configured"
    fi
}

interactive_menu() {
    while true; do
        echo
        echo -e "${BOLD}${CYAN}========================================${NC}"
        echo -e "${BOLD}${CYAN}   Mirage OpenSSH CVE Shield Manager    ${NC}"
        echo -e "${BOLD}${CYAN}========================================${NC}"
        echo "  1) One-Click Deploy (Install + Config + Auto OpenSSH + Systemd)"
        echo "  2) Install / Update Latest Release Binary"
        echo "  3) Auto-Configure Local OpenSSH Upstream (Move sshd to loopback)"
        echo "  4) Restore Original OpenSSH Configuration"
        echo "  5) Edit Configuration / Print sshd & Fail2Ban Guide"
        echo "  6) Service Status"
        echo "  7) Start / Stop / Restart Service"
        echo "  8) View Logs"
        echo "  9) Uninstall Mirage (Restores OpenSSH)"
        echo "  0) Exit"
        echo
        read -rp "Select an option [1]: " opt
        case "${opt:-1}" in
            1) deploy_wizard ;;
            2) install_release ;;
            3) configure_openssh_upstream ;;
            4) restore_openssh_config ;;
            5) edit_config ;;
            6) show_status ;;
            7)
                require_root
                read -rp "Action (start/stop/restart): " act
                case "$act" in
                    start|stop|restart) systemctl "$act" mirage && ok "mirage ${act}ed." ;;
                    *) warn "Invalid action." ;;
                esac
                ;;
            8) show_logs ;;
            9) uninstall_mirage ;;
            0) exit 0 ;;
            *) warn "Invalid option." ;;
        esac
    done
}

usage() {
    cat <<EOF
Usage: $0 [command]

Commands:
  (no args)        Launch interactive management menu
  install [tag]    Download & install latest (or specific) GitHub Release
  deploy           Interactive deployment wizard (with optional auto OpenSSH setup)
  sshd-setup       Automatically move local OpenSSH sshd to loopback upstream port
  sshd-restore     Restore original OpenSSH sshd configuration and port
  edit             Edit /etc/mirage/config.toml or print sshd/Fail2Ban guide
  status           Show installation, OpenSSH drop-in & systemd service status
  start|stop|restart  Control mirage systemd service
  logs             Tail mirage daemon logs
  uninstall        Stop service, restore OpenSSH, and remove binary
  -h, --help       Show this help message
EOF
}

main() {
    local cmd="${1:-}"
    case "$cmd" in
        "")           interactive_menu ;;
        install|update)
            shift
            install_release "${1:-latest}"
            if [[ -t 0 ]]; then
                echo
                read -rp "Run interactive configuration & optional automatic OpenSSH setup now? [Y/n]: " run_wiz
                if [[ "${run_wiz,,}" != "n" ]]; then
                    deploy_wizard --skip-install
                fi
            fi
            ;;
        deploy)       deploy_wizard ;;
        sshd-setup)   shift; configure_openssh_upstream "${1:-}" ;;
        sshd-restore) restore_openssh_config ;;
        edit)         edit_config ;;
        status)       show_status ;;
        start|stop|restart) require_root; systemctl "$cmd" mirage && ok "mirage ${cmd}ed." ;;
        logs)         show_logs ;;
        uninstall)    uninstall_mirage ;;
        -h|--help)    usage ;;
        *)            err "Unknown command: $cmd"; usage; exit 1 ;;
    esac
}

main "$@"
