#!/bin/bash
#===============================================================================
# File: install.sh
# Purpose: IPFire Encryption PKI – 1-Click Installer/Uninstaller
# Version: 2.0.0 – GitHub RAW + Dry-Run + alternatives
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
CONFIG_FILE="${CONFDIR}/encryption.conf"
WRAPPER="/var/ipfire/encryption/gpg/bin/sendmail.gpg.pl"
DISPATCHER="/var/ipfire/encryption/gpg/bin/sendmail.dispatcher.pl"
ALTERNATIVES="/usr/sbin/alternatives"

REPO="ummeegge/IPFire-Encryption-PKI"
BRANCH="main"
BASE_URL="https://raw.githubusercontent.com/${REPO}/refs/heads/${BRANCH}"

BACKUP_DIR="/var/ipfire/backup/encryption-pki"
LOG_FILE="/var/log/encryption-pki-install.log"
TMP_DIR="/tmp/encryption-install-$$"

# === FILES TO DOWNLOAD (repo_path → system_path) ===
declare -A INSTALL_FILES=(
    ["srv_cgi-bin/encryption.cgi"]="/srv/web/ipfire/cgi-bin/encryption.cgi"
    ["srv_cgi-bin/mail.cgi"]="/srv/web/ipfire/cgi-bin/mail.cgi"
    ["var_ipfire/gpg-functions.pl"]="/var/ipfire/encryption/gpg/functions/gpg-functions.pl"
    ["var_ipfire/sendmail.dispatcher.pl"]="$DISPATCHER"
    ["var_ipfire/sendmail.gpg.pl"]="$WRAPPER"
)

# === DIRECTORIES TO MANAGE ===
OUR_DIRS=(
    "$GPGDIR"
    "$CONFDIR"
    "$LOGDIR"
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
warn()  { echo -e "${YELLOW}[WARN] $*${NC}" | tee -a "$LOG_FILE"; }

# === CHECK ROOT ===
[[ $EUID -eq 0 ]] || error "This script must be run as root"

# === USAGE ===
usage() {
    cat << EOF
Usage: $0 {install|uninstall} [options]

COMMANDS:
  install      Download from GitHub + install
  uninstall    Remove module, restore sendmail.dma

OPTIONS:
  --dry-run    Show actions only (no changes)
  --full       Remove everything (default)
  --keep-gpg   Keep GPG keyring and config

EXAMPLES:
  curl -sL https://raw.githubusercontent.com/ummeegge/IPFire-Encryption-PKI/main/install.sh | bash -s -- install
  $0 install
  $0 uninstall --keep-gpg
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

    dry chown nobody:nobody "$dest"
    dry chmod 755 "$dest"
    log "Installed: $repo_path → $dest"
}

# === INSTALL MODE ===
install_mode() {
    log "Starting installation from GitHub..."

    # 1. Create directories
    for dir in "${OUR_DIRS[@]}"; do
        if [[ ! -d "$dir" ]]; then
            dry mkdir -p "$dir"
            log "Created: $dir"
        else
            log "Exists: $dir"
        fi
    done

    # 2. Set permissions
    dry chown nobody:nobody "$GPGDIR" "$LOGDIR" "$CONFDIR" 2>/dev/null || true
    dry chmod 700 "$GPGDIR"
    dry chmod 750 "$LOGDIR" "$CONFDIR"

    # 3. Initialize GPG keyring
    if ! ls "$GPGDIR"/pubring.* >/dev/null 2>&1 && ! ls "$GPGDIR"/secring.* >/dev/null 2>&1; then
        log "Initializing GPG keyring..."
        dry su -s /bin/sh nobody -c "/usr/bin/gpg --homedir '$GPGDIR' --list-keys >/dev/null 2>&1" || true
    fi

    # 4. Fix keyring permissions
    if [[ -d "$GPGDIR" ]]; then
        dry chown -R nobody:nobody "$GPGDIR"
        dry find "$GPGDIR" -type f -exec chmod 600 {} \;
        log "GPG keyring permissions fixed"
    fi

    # 5. Create config if missing
    if [[ ! -f "$CONFIG_FILE" ]]; then
        dry tee "$CONFIG_FILE" > /dev/null << 'EOF'
# IPFire GPG Encryption Module Configuration
# DO NOT EDIT MANUALLY – managed by encryption.cgi
GPGDIR=/var/ipfire/encryption/gpg/keys
LOGFILE=/var/log/encryption/gpgmail.log
TRUSTMODEL=always
DEBUG=off
EOF
        dry chown root:nobody "$CONFIG_FILE"
        dry chmod 660 "$CONFIG_FILE"
        log "Created default config"
    else
        log "Config exists"
    fi

    # 6. Download and install files
    for repo_path in "${!INSTALL_FILES[@]}"; do
        dest="${INSTALL_FILES[$repo_path]}"
        download_file "$repo_path" "$dest"
    done

    # 7. Set up alternatives
    if [[ -x "$WRAPPER" ]]; then
        if ! "$ALTERNATIVES" --display sendmail 2>/dev/null | grep -q "$WRAPPER"; then
            dry "$ALTERNATIVES" --install /usr/sbin/sendmail sendmail "$WRAPPER" 30
            log "sendmail.gpg.pl added to alternatives"
        fi
    fi

    # 8. Symlink
    if [[ -x "$WRAPPER" ]] && [[ ! -e /usr/sbin/sendmail.gpg ]]; then
        dry ln -sf "$WRAPPER" /usr/sbin/sendmail.gpg
        log "Symlink created: /usr/sbin/sendmail.gpg"
    fi

    log "Installation completed!"
    echo
    echo "Visit: https://your-ipfire/cgi-bin/encryption.cgi"
    echo "Press 'Save' to activate!"
}

# === UNINSTALL MODE ===
uninstall_mode() {
    local keep_gpg=false
    [[ " $* " == *" --keep-gpg "* ]] && keep_gpg=true

    log "Starting uninstallation..."

    # 1. Restore sendmail.dma
    if "$ALTERNATIVES" --display sendmail 2>/dev/null | grep -q "$WRAPPER"; then
        dry "$ALTERNATIVES" --remove sendmail "$WRAPPER" || true
        log "Removed from alternatives"
    fi
    if [[ -x /usr/sbin/sendmail.dma ]]; then
        if ! "$ALTERNATIVES" --display sendmail 2>/dev/null | grep -q "/usr/sbin/sendmail.dma.*20"; then
            dry "$ALTERNATIVES" --install /usr/sbin/sendmail sendmail /usr/sbin/sendmail.dma 20
            log "Restored sendmail.dma"
        fi
    fi

    # 2. Remove symlink
    [[ -L /usr/sbin/sendmail.gpg ]] && dry rm -f /usr/sbin/sendmail.gpg && log "Removed symlink"

    # 3. Remove our files
    for repo_path in "${!INSTALL_FILES[@]}"; do
        dest="${INSTALL_FILES[$repo_path]}"
        if [[ -f "$dest" ]]; then
            dry rm -f "$dest"
            log "Removed: $dest"
        fi
    done

    # 4. Remove config (if default)
    if [[ -f "$CONFIG_FILE" ]] && ! grep -q "^GPG_KEY=\|DEBUG=on" "$CONFIG_FILE"; then
        dry rm -f "$CONFIG_FILE"
        log "Removed default config"
    fi

    # 5. Remove directories (if keep_gpg = false)
    if ! $keep_gpg; then
        for dir in "${OUR_DIRS[@]}"; do
            if [[ -d "$dir" ]]; then
                dry rm -rf "$dir"
                log "Removed: $dir"
            fi
        done
    else
        warn "Keeping GPG keyring: $GPGDIR"
    fi

    log "Uninstallation completed."
}

# === MAIN ===
main() {
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
