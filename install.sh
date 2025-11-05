#!/bin/bash
#===============================================================================
# File: install.sh
# Purpose: IPFire Encryption PKI – 1-Click Installer/Uninstaller
# Version: 3.3.0 – FINAL: direct dma, no loop, full backup, alternatives fix
#===============================================================================
set -euo pipefail

# === COLORS ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# === CONFIG ===
MODULE_NAME="encryption"
BASEDIR="/var/ipfire/encryption"
GPGDIR="${BASEDIR}/gpg/keys"
CONFDIR="${BASEDIR}/gpg/conf"
LOGDIR="/var/log/encryption"
CENTRAL_LOG="${LOGDIR}/encryption.log"
CONFIG_FILE="${CONFDIR}/encryption.conf"
DISPATCHER="/var/ipfire/encryption/gpg/bin/sendmail.dispatcher.pl"
WRAPPER="/var/ipfire/encryption/gpg/bin/sendmail.gpg.pl"
DMA_BINARY="/usr/sbin/dma"
DMA_BACKUP="/usr/sbin/sendmail.dma.bak"  # ← NEU: Backup des Originals!
REPO="ummeegge/IPFire-Encryption-PKI"
BRANCH="main"
BASE_URL="https://raw.githubusercontent.com/${REPO}/refs/heads/${BRANCH}"
BACKUP_DIR="/var/ipfire/backup/encryption-pki"
MAIL_CGI_ORIG="/srv/web/ipfire/cgi-bin/mail.cgi.bck-orig"
LOG_FILE="/var/log/encryption-pki-install.log"

# === FILES TO DOWNLOAD ===
declare -A INSTALL_FILES=(
    ["srv_cgi-bin/encryption.cgi"]="/srv/web/ipfire/cgi-bin/encryption.cgi"
    ["srv_cgi-bin/mail.cgi"]="/srv/web/ipfire/cgi-bin/mail.cgi"
    ["var_ipfire/gpg-functions.pl"]="/var/ipfire/encryption/gpg/functions/gpg-functions.pl"
    ["var_ipfire/sendmail.dispatcher.pl"]="$DISPATCHER"
    ["var_ipfire/sendmail.gpg.pl"]="$WRAPPER"
    ["var_ipfire/logging.pl"]="/var/ipfire/encryption/logging/logging.pl"
)

# === DIRECTORIES TO MANAGE ===
OUR_DIRS=(
    "$GPGDIR"
    "$CONFDIR"
    "$LOGDIR"
    "/var/ipfire/encryption/logging"
)

# === DRY-RUN ===
DRY_RUN=false
if [[ " $* " == *" --dry-run "* ]]; then
    DRY_RUN=true
    log() { echo -e "${BLUE}[DRY] $*${NC}" | tee -a "$LOG_FILE"; }
else
    log() { echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $*${NC}" | tee -a "$LOG_FILE"; }
fi

dry() {
    if $DRY_RUN; then
        echo "[DRY] $*"
    else
        "$@"
    fi
}

error() { echo -e "${RED}[ERROR] $*${NC}" >&2 | tee -a "$LOG_FILE"; exit 1; }
warn() { echo -e "${YELLOW}[WARN] $*${NC}" | tee -a "$LOG_FILE"; }

# === CHECK ROOT ===
[[ $EUID -eq 0 ]] || error "This script must be run as root"

# === USAGE ===
usage() {
    cat << EOF
Usage: $0 {install|uninstall} [options]
COMMANDS:
  install     Download from GitHub + install
  uninstall   Remove module, restore sendmail.dma + alternatives
OPTIONS:
  --dry-run   Show actions only
  --full      Remove everything (including GPG keys)
  --keep-gpg  Keep GPG keyring during uninstall
EOF
    exit 1
}

# === DOWNLOAD FILE ===
download_file() {
    local repo_path="$1"
    local dest="$2"
    local url="${BASE_URL}/${repo_path}"
    dry mkdir -p "$(dirname "$dest")"
    log "Downloading: $url → $dest"
    if ! dry curl -fsL -o "$dest" "$url"; then
        error "Failed to download: $url"
    fi
    case "$dest" in
        *.pl)
            dry chown nobody:nobody "$dest"
            dry chmod 755 "$dest"
            ;;
        *.cgi)
            dry chown root:root "$dest"
            dry chmod 755 "$dest"
            ;;
        *)
            dry chown nobody:nobody "$dest"
            dry chmod 644 "$dest"
            ;;
    esac
    log "Installed: $repo_path → $dest"
}

# === BACKUP/RESTORE mail.cgi ===
backup_mail_cgi() {
    local target="/srv/web/ipfire/cgi-bin/mail.cgi"
    if [[ -f "$target" ]] && [[ ! -f "$MAIL_CGI_ORIG" ]]; then
        dry cp "$target" "$MAIL_CGI_ORIG"
        log "Backed up original mail.cgi → $MAIL_CGI_ORIG"
    fi
}

restore_mail_cgi() {
    local target="/srv/web/ipfire/cgi-bin/mail.cgi"
    if [[ -f "$MAIL_CGI_ORIG" ]]; then
        dry cp "$MAIL_CGI_ORIG" "$target"
        dry chown root:root "$target"
        dry chmod 755 "$target"
        log "Restored original mail.cgi"
    fi
}

# === INSTALL MODE ===
install_mode() {
    log "Starting installation..."

    # 1. Backup original mail.cgi
    backup_mail_cgi

    # 2. Create directories
    for dir in "${OUR_DIRS[@]}"; do
        [[ ! -d "$dir" ]] && dry mkdir -p "$dir" && log "Created: $dir"
    done

    # 3. Permissions
    dry chown nobody:nobody "$GPGDIR" "$LOGDIR" "$CONFDIR" "/var/ipfire/encryption/logging" 2>/dev/null || true
    dry chmod 700 "$GPGDIR"
    dry chmod 750 "$LOGDIR" "$CONFDIR"
    dry chmod 755 "/var/ipfire/encryption/logging"

    # 4. Initialize GPG keyring
    if ! ls "$GPGDIR"/pubring.* >/dev/null 2>&1 && ! ls "$GPGDIR"/secring.* >/dev/null 2>&1; then
        log "Initializing GPG keyring..."
        dry su -s /bin/sh nobody -c "/usr/bin/gpg --homedir '$GPGDIR' --list-keys >/dev/null 2>&1" || true
    fi
    if [[ -d "$GPGDIR" ]]; then
        dry chown -R nobody:nobody "$GPGDIR"
        dry find "$GPGDIR" -type f -exec chmod 600 {} \;
        log "GPG keyring permissions fixed"
    fi

    # 5. Create default config
    if [[ ! -f "$CONFIG_FILE" ]]; then
        dry tee "$CONFIG_FILE" > /dev/null << 'EOF'
GPGDIR=/var/ipfire/encryption/gpg/keys
TRUSTMODEL=always
DEBUG=off
LOG_LEVEL=2
EOF
        dry chown root:nobody "$CONFIG_FILE"
        dry chmod 660 "$CONFIG_FILE"
        log "Created default config"
    fi

    # 6. Download all files
    for repo_path in "${!INSTALL_FILES[@]}"; do
        dest="${INSTALL_FILES[$repo_path]}"
        download_file "$repo_path" "$dest"
    done

    # 7. BACKUP ORIGINAL DMA BINARY
    if [[ ! -f "$DMA_BACKUP" ]]; then
        dry cp "$DMA_BINARY" "$DMA_BACKUP"
        log "Backup: $DMA_BACKUP ← $DMA_BINARY"
    fi

    # 8. SET SYMLINK: sendmail.dma → dispatcher
    if [[ -x "$DISPATCHER" ]]; then
        dry rm -f /usr/sbin/sendmail.dma
        dry ln -sf "$DISPATCHER" /usr/sbin/sendmail.dma
        log "Symlink: /usr/sbin/sendmail.dma → dispatcher"
    fi

    # 9. Create central log
    if [[ ! -f "$CENTRAL_LOG" ]]; then
        dry touch "$CENTRAL_LOG"
        dry chown nobody:nobody "$CENTRAL_LOG"
        dry chmod 644 "$CENTRAL_LOG"
        log "Created central log: $CENTRAL_LOG"
    fi

    log "Installation completed!"
    echo "Visit: https://$(hostname)/cgi-bin/encryption.cgi"
    echo "Log: tail -f $CENTRAL_LOG"
}

# === UNINSTALL MODE ===
uninstall_mode() {
    local keep_gpg=false
    local full=false
    [[ " $* " == *" --keep-gpg "* ]] && keep_gpg=true
    [[ " $* " == *" --full "* ]] && full=true

    log "Starting uninstallation..."

    # 1. RESTORE sendmail.dma → original dma
    if [[ -L /usr/sbin/sendmail.dma ]] && [[ $(readlink /usr/sbin/sendmail.dma) == "$DISPATCHER" ]]; then
        dry rm -f /usr/sbin/sendmail.dma
        if [[ -f "$DMA_BACKUP" ]]; then
            dry cp "$DMA_BACKUP" "$DMA_BINARY"
            log "Restored original $DMA_BINARY from backup"
        else
            dry ln -sf "$DMA_BINARY" /usr/sbin/sendmail.dma
            log "Fallback: sendmail.dma → $DMA_BINARY"
        fi
    fi

    # 2. RESTORE alternatives
    if [[ -x /usr/sbin/alternatives ]]; then
        dry /usr/sbin/alternatives --install /usr/sbin/sendmail sendmail /usr/sbin/sendmail.dma 20 || true
        log "Restored alternatives: sendmail.dma priority 20"
    fi

    # 3. Remove installed files
    for repo_path in "${!INSTALL_FILES[@]}"; do
        dest="${INSTALL_FILES[$repo_path]}"
        [[ "$dest" == "/srv/web/ipfire/cgi-bin/mail.cgi" ]] && continue
        [[ -f "$dest" ]] && dry rm -f "$dest" && log "Removed: $dest"
    done

    # 4. Restore mail.cgi
    restore_mail_cgi

    # 5. Remove config (if default)
    if [[ -f "$CONFIG_FILE" ]] && ! grep -q "^GPG_KEY=\|DEBUG=on" "$CONFIG_FILE"; then
        dry rm -f "$CONFIG_FILE"
        log "Removed default config"
    fi

    # 6. Remove directories
    if ! $keep_gpg || $full; then
        for dir in "${OUR_DIRS[@]}"; do
            [[ -d "$dir" ]] && dry rm -rf "$dir" && log "Removed: $dir"
        done
        [[ -f "$MAIL_CGI_ORIG" ]] && dry rm -f "$MAIL_CGI_ORIG" && log "Removed mail.cgi backup"
        [[ -f "$DMA_BACKUP" ]] && dry rm -f "$DMA_BACKUP" && log "Removed DMA backup"
    fi

    log "Uninstallation completed."
}

# === MAIN ===
main() {
    mkdir -p "$BACKUP_DIR"
    touch "$LOG_FILE"
    case "${1:-}" in
        install) install_mode ;;
        uninstall) shift; uninstall_mode "$@" ;;
        --help|-h) usage ;;
        *) error "Invalid command"; usage ;;
    esac
}

main "$@"
exit 0