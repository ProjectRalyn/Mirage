#!/usr/bin/env bash
# Mirage All-in-One Deployment, Configuration & Management Script
# Repository: https://github.com/ProjectRalyn/Mirage
set -euo pipefail

REPO="ProjectRalyn/Mirage"
DAEMON_BIN="/usr/local/bin/mirage-daemon"
FAKE_SHELL_BIN="/usr/local/bin/mirage-fake-shell"
PAM_SO_DIR="/usr/local/lib/security"
PAM_SO_PATH="${PAM_SO_DIR}/libpam_mirage.so"
CONFIG_DIR="/etc/mirage"
CONFIG_FILE="${CONFIG_DIR}/config.toml"
SERVICE_FILE="/etc/systemd/system/mirage.service"
PAM_SSHD_FILE="/etc/pam.d/sshd"
PAM_SSHD_BAK="/etc/pam.d/sshd.mirage.bak"
SSHD_DROPIN_DIR="/etc/ssh/sshd_config.d"
SSHD_DROPIN_FILE="${SSHD_DROPIN_DIR}/99-mirage.conf"
PAM_LOG_FILE="/var/log/mirage-pam.jsonl"
PAM_STATE_DIR="/tmp/mirage-pam-state"

# Colors
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

check_pam_so_compat() {
    if [[ -f "$PAM_SO_PATH" ]] && command -v ldd >/dev/null 2>&1; then
        local ldd_out
        ldd_out="$(ldd "$PAM_SO_PATH" 2>&1 || true)"
        if echo "$ldd_out" | grep -qiE "not found|GLIBC_.*not found"; then
            warn "libpam_mirage.so compatibility check detected missing libraries/symbols:"
            echo "$ldd_out" | grep -iE "not found|GLIBC_" || true
            return 1
        fi
    fi
    return 0
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
    else
        warn "SHA256SUMS.txt not found in release; skipping checksum verification."
    fi

    info "Extracting release archive..."
    tar -xzf "${tmp_dir}/${archive_name}" -C "$tmp_dir"

    install -d -m 0755 /usr/local/bin "$PAM_SO_DIR" "$CONFIG_DIR"
    install -m 0755 "${tmp_dir}/mirage-daemon" "$DAEMON_BIN"
    install -m 0755 "${tmp_dir}/mirage-fake-shell" "$FAKE_SHELL_BIN"
    install -m 0755 "${tmp_dir}/libpam_mirage.so" "$PAM_SO_PATH"

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

    ok "Installed binaries and libpam_mirage.so:"
    echo "  - $DAEMON_BIN"
    echo "  - $FAKE_SHELL_BIN"
    echo "  - $PAM_SO_PATH"

    check_pam_so_compat || warn "You can still use mirage-daemon standalone/frontline_proxy, or build from source for libpam_mirage.so."

    if systemctl is-active --quiet mirage 2>/dev/null; then
        info "Restarting running mirage service..."
        systemctl restart mirage
        ok "Mirage service restarted."
    fi
}

write_systemd_service() {
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Mirage Asymmetric Deception & Tarpit Honeypot Daemon
After=network-online.target
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

set_toml_key_in_section() {
    # Usage: set_toml_key_in_section <file> <section_or_root> <key> <value_literal>
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
        warn "python3 not found; skipping automatic update of [${section}] ${key}. Please edit ${CONFIG_FILE} manually."
    fi
}

deploy_wizard() {
    require_root
    if [[ ! -x "$DAEMON_BIN" ]]; then
        install_release
    else
        read -rp "Mirage is already installed. Update to latest release first? [y/N]: " ans
        if [[ "${ans,,}" == "y" ]]; then
            install_release
        fi
    fi

    echo
    echo -e "${BOLD}=== Mirage One-Click Deployment Wizard ===${NC}"
    echo "Press Enter to accept defaults in [brackets]."
    echo

    # HTTP
    echo "HTTP modes: 1) standalone  2) frontline_proxy  3) behind_proxy_sink"
    read -rp "Select HTTP mode [1]: " http_choice
    local http_mode="standalone"
    case "${http_choice:-1}" in
        1|standalone)        http_mode="standalone" ;;
        2|frontline_proxy)   http_mode="frontline_proxy" ;;
        3|behind_proxy_sink) http_mode="behind_proxy_sink" ;;
        *) warn "Invalid choice, using standalone." ;;
    esac

    read -rp "HTTP bind address [0.0.0.0:8080]: " http_addr
    http_addr="${http_addr:-0.0.0.0:8080}"
    update_toml_value "http" "mode" "\"${http_mode}\""
    update_toml_value "http" "bind_addr" "\"${http_addr}\""

    if [[ "$http_mode" == "frontline_proxy" ]]; then
        read -rp "Real upstream HTTP URL (e.g. http://127.0.0.1:3000): " upstream_http
        if [[ -n "$upstream_http" ]]; then
            update_toml_value "http" "upstream_http_url" "\"${upstream_http}\""
        fi
    fi

    # SSH
    echo
    echo "SSH daemon modes: 1) standalone  2) frontline_proxy"
    read -rp "Select SSH daemon mode [1]: " ssh_choice
    local ssh_mode="standalone"
    case "${ssh_choice:-1}" in
        1|standalone)      ssh_mode="standalone" ;;
        2|frontline_proxy) ssh_mode="frontline_proxy" ;;
        *) warn "Invalid choice, using standalone." ;;
    esac

    read -rp "SSH daemon bind address [0.0.0.0:2222]: " ssh_addr
    ssh_addr="${ssh_addr:-0.0.0.0:2222}"
    update_toml_value "ssh" "mode" "\"${ssh_mode}\""
    update_toml_value "ssh" "bind_addr" "\"${ssh_addr}\""

    if [[ "$ssh_mode" == "frontline_proxy" ]]; then
        read -rp "Real upstream OpenSSH addr [127.0.0.1:22022]: " upstream_ssh
        upstream_ssh="${upstream_ssh:-127.0.0.1:22022}"
        update_toml_value "ssh" "upstream_sshd_addr" "\"${upstream_ssh}\""
    fi

    # Redis & PostgreSQL
    echo
    read -rp "Enable Redis honeypot? [Y/n]: " redis_en
    if [[ "${redis_en,,}" == "n" ]]; then
        update_toml_value "redis" "enabled" "false"
    else
        update_toml_value "redis" "enabled" "true"
        read -rp "Redis bind address [0.0.0.0:16379]: " redis_addr
        update_toml_value "redis" "bind_addr" "\"${redis_addr:-0.0.0.0:16379}\""
    fi

    read -rp "Enable PostgreSQL honeypot? [Y/n]: " pg_en
    if [[ "${pg_en,,}" == "n" ]]; then
        update_toml_value "postgres" "enabled" "false"
    else
        update_toml_value "postgres" "enabled" "true"
        read -rp "PostgreSQL bind address [0.0.0.0:15432]: " pg_addr
        update_toml_value "postgres" "bind_addr" "\"${pg_addr:-0.0.0.0:15432}\""
    fi

    # Rotation & Admin
    echo
    read -rp "Persona rotation interval in seconds [300]: " rot_secs
    update_toml_value "root" "rotation_interval_secs" "${rot_secs:-300}"
    update_toml_value "admin" "path_prefix" "\"auto\""

    write_systemd_service
    systemctl enable --now mirage
    systemctl restart mirage

    echo
    ok "Mirage daemon deployed and started!"
    systemctl --no-pager -l status mirage || true
    echo
    info "Tip: Check the randomized admin panel URL in logs:"
    echo "  journalctl -u mirage -n 30 --no-pager"
    echo

    read -rp "Also configure Native OpenSSH PAM (.so) + ForceCommand on port 22? [y/N]: " setup_pam
    if [[ "${setup_pam,,}" == "y" ]]; then
        pam_setup
    fi
}

pam_setup() {
    require_root
    [[ -f "$PAM_SO_PATH" ]] || die "Missing $PAM_SO_PATH. Run '$0 install' first."
    [[ -x "$FAKE_SHELL_BIN" ]] || die "Missing $FAKE_SHELL_BIN. Run '$0 install' first."
    [[ -f "$PAM_SSHD_FILE" ]] || die "Missing $PAM_SSHD_FILE. Is OpenSSH server installed?"

    if ! check_pam_so_compat; then
        die "Aborting PAM setup because libpam_mirage.so is not compatible with this host's glibc/libpam."
    fi

    echo
    echo -e "${BOLD}=== Native OpenSSH PAM (.so) + ForceCommand Setup ===${NC}"
    echo "Real users are unaffected (PAM_IGNORE). Decoy users are trapped into mirage-fake-shell."
    echo

    read -rp "Decoy usernames (comma-separated) [svc_deploy,admin,test,ubnt,postgres]: " decoy_users
    decoy_users="${decoy_users:-svc_deploy,admin,test,ubnt,postgres}"
    read -rp "Accept password on N-th attempt [3]: " accept_on
    accept_on="${accept_on:-3}"
    read -rp "Auth fail delay in ms [1200]: " fail_delay
    fail_delay="${fail_delay:-1200}"

    # Create decoy system users
    IFS=',' read -ra USERS <<< "$decoy_users"
    for u in "${USERS[@]}"; do
        u="$(echo "$u" | xargs)"
        [[ -z "$u" ]] && continue
        if id "$u" >/dev/null 2>&1; then
            warn "User '$u' already exists; skipping useradd (ForceCommand in sshd_config will still apply)."
        else
            useradd -M -s "$FAKE_SHELL_BIN" "$u"
            ok "Created decoy user: $u"
        fi
    done

    # Backup /etc/pam.d/sshd
    if [[ ! -f "$PAM_SSHD_BAK" ]]; then
        cp "$PAM_SSHD_FILE" "$PAM_SSHD_BAK"
        ok "Backed up ${PAM_SSHD_FILE} to ${PAM_SSHD_BAK}"
    fi

    local pam_line="auth sufficient ${PAM_SO_PATH} decoy_users=${decoy_users} accept_on=${accept_on} fail_delay_ms=${fail_delay} config=${CONFIG_FILE} state_dir=${PAM_STATE_DIR} log_file=${PAM_LOG_FILE}"

    # Remove any previous mirage line and prepend new one
    local tmp_pam
    tmp_pam="$(mktemp)"
    {
        echo "# Mirage PAM deception module"
        echo "$pam_line"
        grep -v "libpam_mirage\.so" "$PAM_SSHD_FILE" | grep -v "^# Mirage PAM deception module$" || true
    } > "$tmp_pam"
    cat "$tmp_pam" > "$PAM_SSHD_FILE"
    rm -f "$tmp_pam"
    ok "Updated ${PAM_SSHD_FILE}"

    # Write sshd_config.d drop-in
    install -d -m 0755 "$SSHD_DROPIN_DIR"
    cat > "$SSHD_DROPIN_FILE" <<EOF
# Managed by mirage.sh - Native OpenSSH PAM + ForceCommand Deception
UsePAM yes
KbdInteractiveAuthentication yes

Match User ${decoy_users}
    PasswordAuthentication yes
    PermitEmptyPasswords no
    ForceCommand ${FAKE_SHELL_BIN}
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
    AllowAgentForwarding no
EOF
    ok "Wrote ${SSHD_DROPIN_FILE}"

    # Ensure sshd_config includes sshd_config.d if present
    if [[ -f /etc/ssh/sshd_config ]] && ! grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
        warn "/etc/ssh/sshd_config does not appear to include /etc/ssh/sshd_config.d/*.conf!"
        warn "Please verify your OpenSSH version supports Include or merge ${SSHD_DROPIN_FILE} manually."
    fi

    # Validate sshd config before reloading
    if command -v sshd >/dev/null 2>&1; then
        if ! sshd -t; then
            err "sshd -t validation failed! Rolling back PAM and sshd changes..."
            cp "$PAM_SSHD_BAK" "$PAM_SSHD_FILE"
            rm -f "$SSHD_DROPIN_FILE"
            die "Rollback complete. Your SSH daemon was NOT modified."
        fi
        ok "sshd -t configuration check passed."
        if systemctl is-active --quiet sshd 2>/dev/null; then
            systemctl reload sshd
        elif systemctl is-active --quiet ssh 2>/dev/null; then
            systemctl reload ssh
        else
            warn "Could not detect ssh/sshd systemd service; please reload sshd manually."
        fi
        ok "OpenSSH reloaded with Mirage PAM deception active!"
    fi
}

edit_config() {
    require_root
    [[ -f "$CONFIG_FILE" ]] || die "Config file not found at ${CONFIG_FILE}. Run '$0 deploy' or '$0 install' first."

    echo
    echo -e "${BOLD}=== Edit Mirage Configuration ===${NC}"
    echo "1) Open ${CONFIG_FILE} in editor (${EDITOR:-nano/vi})"
    echo "2) Quick-edit common settings (ports / modes / rotation)"
    echo "3) Print Nginx behind_proxy_sink config"
    echo "4) Print Caddy behind_proxy_sink config"
    echo "5) Print OpenSSH integration guide"
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
                if [[ "${r,,}" != "n" ]]; then
                    systemctl restart mirage
                    ok "Mirage restarted."
                fi
            fi
            ;;
        2)
            read -rp "HTTP bind_addr (leave blank to keep current): " v
            [[ -n "$v" ]] && update_toml_value "http" "bind_addr" "\"$v\""
            read -rp "HTTP mode (standalone/frontline_proxy/behind_proxy_sink, blank to keep): " v
            [[ -n "$v" ]] && update_toml_value "http" "mode" "\"$v\""
            read -rp "SSH bind_addr (leave blank to keep): " v
            [[ -n "$v" ]] && update_toml_value "ssh" "bind_addr" "\"$v\""
            read -rp "Rotation interval secs (leave blank to keep): " v
            [[ -n "$v" ]] && update_toml_value "root" "rotation_interval_secs" "$v"
            ok "Updated ${CONFIG_FILE}."
            if systemctl is-active --quiet mirage 2>/dev/null; then
                systemctl restart mirage && ok "Mirage restarted."
            fi
            ;;
        3) "$DAEMON_BIN" --print-nginx-config ;;
        4) "$DAEMON_BIN" --print-caddy-config ;;
        5) "$DAEMON_BIN" --print-sshd-config ;;
        0) return 0 ;;
        *) warn "Invalid option." ;;
    esac
}

show_logs() {
    echo "1) Mirage daemon logs (journalctl -u mirage)"
    echo "2) Mirage PAM SSH auth log (${PAM_LOG_FILE})"
    read -rp "Choose [1]: " c
    case "${c:-1}" in
        1) journalctl -u mirage -n 50 -f ;;
        2)
            if [[ -f "$PAM_LOG_FILE" ]]; then
                tail -n 50 -f "$PAM_LOG_FILE"
            else
                warn "No PAM log file found at ${PAM_LOG_FILE} yet."
            fi
            ;;
    esac
}

uninstall_mirage() {
    require_root
    echo -e "${YELLOW}This will stop Mirage, remove binaries/PAM module, and clean up sshd/PAM hooks.${NC}"
    read -rp "Continue? [y/N]: " confirm
    [[ "${confirm,,}" == "y" ]] || { info "Cancelled."; return 0; }

    if systemctl list-unit-files | grep -q "^mirage\.service"; then
        systemctl stop mirage 2>/dev/null || true
        systemctl disable mirage 2>/dev/null || true
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
        ok "Removed systemd service."
    fi

    if [[ -f "$PAM_SSHD_FILE" ]] && grep -q "libpam_mirage\.so" "$PAM_SSHD_FILE"; then
        local tmp_pam
        tmp_pam="$(mktemp)"
        grep -v "libpam_mirage\.so" "$PAM_SSHD_FILE" | grep -v "^# Mirage PAM deception module$" > "$tmp_pam" || true
        cat "$tmp_pam" > "$PAM_SSHD_FILE"
        rm -f "$tmp_pam"
        ok "Removed Mirage hook from ${PAM_SSHD_FILE}"
    fi

    if [[ -f "$SSHD_DROPIN_FILE" ]]; then
        rm -f "$SSHD_DROPIN_FILE"
        ok "Removed ${SSHD_DROPIN_FILE}"
        if command -v sshd >/dev/null 2>&1 && sshd -t 2>/dev/null; then
            systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
        fi
    fi

    rm -f "$DAEMON_BIN" "$FAKE_SHELL_BIN" "$PAM_SO_PATH"
    ok "Removed binaries and libpam_mirage.so."

    read -rp "Also remove config directory ${CONFIG_DIR} and PAM logs? [y/N]: " rm_cfg
    if [[ "${rm_cfg,,}" == "y" ]]; then
        rm -rf "$CONFIG_DIR" "$PAM_LOG_FILE" "$PAM_STATE_DIR" "$PAM_SSHD_BAK"
        ok "Removed configuration and logs."
    fi
}

show_status() {
    echo -e "${BOLD}=== Mirage Status ===${NC}"
    if [[ -x "$DAEMON_BIN" ]]; then
        ok "Binary: $DAEMON_BIN"
    else
        warn "Binary not installed"
    fi
    if [[ -f "$PAM_SO_PATH" ]]; then
        ok "PAM .so: $PAM_SO_PATH"
    else
        warn "PAM .so not installed"
    fi
    if [[ -f "$CONFIG_FILE" ]]; then
        ok "Config: $CONFIG_FILE"
    else
        warn "Config not found"
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
        echo -e "${BOLD}${CYAN}      Mirage Deception Manager          ${NC}"
        echo -e "${BOLD}${CYAN}========================================${NC}"
        echo "  1) One-Click Deploy (Install + Config + Systemd)"
        echo "  2) Install / Update Latest Release Binaries & .so"
        echo "  3) Configure Native OpenSSH PAM (.so) + ForceCommand"
        echo "  4) Edit Configuration / Print Nginx & Caddy Templates"
        echo "  5) Service Status"
        echo "  6) Start / Stop / Restart Service"
        echo "  7) View Logs (Daemon / PAM)"
        echo "  8) Uninstall Mirage"
        echo "  0) Exit"
        echo
        read -rp "Select an option [1]: " opt
        case "${opt:-1}" in
            1) deploy_wizard ;;
            2) install_release ;;
            3) pam_setup ;;
            4) edit_config ;;
            5) show_status ;;
            6)
                require_root
                read -rp "Action (start/stop/restart): " act
                case "$act" in
                    start|stop|restart) systemctl "$act" mirage && ok "mirage ${act}ed." ;;
                    *) warn "Invalid action." ;;
                esac
                ;;
            7) show_logs ;;
            8) uninstall_mirage ;;
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
  deploy           Run interactive one-click deployment wizard
  pam-setup        Configure Native OpenSSH PAM (.so) + ForceCommand
  edit             Edit /etc/mirage/config.toml or print proxy templates
  status           Show installation & systemd service status
  start|stop|restart  Control mirage systemd service
  logs             Tail mirage daemon or PAM logs
  uninstall        Stop service, remove PAM hooks and binaries
  -h, --help       Show this help message
EOF
}

main() {
    local cmd="${1:-}"
    case "$cmd" in
        "")           interactive_menu ;;
        install|update) shift; install_release "${1:-latest}" ;;
        deploy)       deploy_wizard ;;
        pam-setup)    pam_setup ;;
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
