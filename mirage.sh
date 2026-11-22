#!/usr/bin/env bash
# Mirage Frontline OpenSSH Reverse Proxy & Pre-Auth CVE Shield Manager
# Repository: https://github.com/ProjectRalyn/Mirage
set -euo pipefail

REPO="ProjectRalyn/Mirage"
DAEMON_BIN="/usr/local/bin/mirage-daemon"
CONFIG_DIR="/etc/mirage"
CONFIG_FILE="${CONFIG_DIR}/config.toml"
SERVICE_FILE="/etc/systemd/system/mirage.service"
SSHD_DROPIN_FILE="/etc/ssh/sshd_config.d/99-mirage-upstream.conf"

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

    update_toml_value "ssh" "bind_addr" "\"${ssh_addr}\""
    update_toml_value "ssh" "upstream_sshd_addr" "\"${upstream_ssh}\""
    update_toml_value "ssh" "bruteforce_action" "\"${bf_action}\""
    update_toml_value "ssh" "cve_exploit_action" "\"${cve_action}\""
    update_toml_value "ssh" "scanner_action" "\"${sc_action}\""

    write_systemd_service
    systemctl enable --now mirage
    systemctl restart mirage

    echo
    ok "Mirage Frontline SSH Shield started!"
    echo
    "$DAEMON_BIN" --config "$CONFIG_FILE" --print-sshd-config
}

edit_config() {
    require_root
    [[ -f "$CONFIG_FILE" ]] || die "Config file not found at ${CONFIG_FILE}. Run '$0 deploy' or '$0 install' first."

    echo
    echo -e "${BOLD}=== Edit Mirage Configuration ===${NC}"
    echo "1) Open ${CONFIG_FILE} in editor (${EDITOR:-nano/vi})"
    echo "2) Print upstream OpenSSH sshd setup guide"
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
    echo -e "${YELLOW}This will stop Mirage and remove its binary and systemd unit.${NC}"
    read -rp "Continue? [y/N]: " confirm
    [[ "${confirm,,}" == "y" ]] || { info "Cancelled."; return 0; }

    if systemctl list-unit-files | grep -q "^mirage\.service"; then
        systemctl stop mirage 2>/dev/null || true
        systemctl disable mirage 2>/dev/null || true
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
        ok "Removed systemd service."
    fi

    rm -f "$DAEMON_BIN"
    ok "Removed ${DAEMON_BIN}."

    read -rp "Also remove config directory ${CONFIG_DIR}? [y/N]: " rm_cfg
    if [[ "${rm_cfg,,}" == "y" ]]; then
        rm -rf "$CONFIG_DIR"
        ok "Removed configuration."
    fi
}

show_status() {
    echo -e "${BOLD}=== Mirage Status ===${NC}"
    [[ -x "$DAEMON_BIN" ]] && ok "Binary: $DAEMON_BIN" || warn "Binary not installed"
    [[ -f "$CONFIG_FILE" ]] && ok "Config: $CONFIG_FILE" || warn "Config not found"
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
        echo "  1) One-Click Deploy (Install + Config + Systemd)"
        echo "  2) Install / Update Latest Release Binary"
        echo "  3) Edit Configuration / Print sshd Proxy Guide"
        echo "  4) Service Status"
        echo "  5) Start / Stop / Restart Service"
        echo "  6) View Logs"
        echo "  7) Uninstall Mirage"
        echo "  0) Exit"
        echo
        read -rp "Select an option [1]: " opt
        case "${opt:-1}" in
            1) deploy_wizard ;;
            2) install_release ;;
            3) edit_config ;;
            4) show_status ;;
            5)
                require_root
                read -rp "Action (start/stop/restart): " act
                case "$act" in
                    start|stop|restart) systemctl "$act" mirage && ok "mirage ${act}ed." ;;
                    *) warn "Invalid action." ;;
                esac
                ;;
            6) show_logs ;;
            7) uninstall_mirage ;;
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
  deploy           Run interactive frontline proxy deployment wizard
  edit             Edit /etc/mirage/config.toml or print sshd proxy guide
  status           Show installation & systemd service status
  start|stop|restart  Control mirage systemd service
  logs             Tail mirage daemon logs
  uninstall        Stop service and remove binary
  -h, --help       Show this help message
EOF
}

main() {
    local cmd="${1:-}"
    case "$cmd" in
        "")           interactive_menu ;;
        install|update) shift; install_release "${1:-latest}" ;;
        deploy)       deploy_wizard ;;
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
