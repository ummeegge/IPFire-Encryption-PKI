#!/bin/bash
#===============================================================================
# File: install.sh
# Purpose: IPFire Encryption PKI – Installer/Uninstaller
# Version: 3.3.6 – NO hardcoded FROM, SENDER from mail.conf only
#===============================================================================
set -euo pipefail

# === COLORS ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# === CONFIGURATION ===
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
SENDMAIL_DMA="/usr/sbin/sendmail.dma"
SENDMAIL_DMA_BACKUP="/usr/sbin/sendmail.dma.bck"
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

# === DRY-RUN FLAG ===
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

error() {
  echo -e "${RED}[ERROR] $*${NC}" >&2 | tee -a "$LOG_FILE"
  exit 1
}

warn() { echo -e "${YELLOW}[WARN] $*${NC}" | tee -a "$LOG_FILE"; }

# === CHECK FOR ROOT USER ===
[[ $EUID -eq 0 ]] || error "This script must be run as root"

# === DISPLAY USAGE INFO ===
usage() {
  cat << EOF
Usage: $0 {install|uninstall} [options]
COMMANDS:
  install     Download from GitHub and install
  uninstall   Remove module, restore original sendmail.dma, alternatives, and mail.cgi
OPTIONS:
  --dry-run   Display actions only, no changes made
  --full      Remove everything including GPG keys
  --keep-gpg  Retain GPG keyring during uninstall
EOF
  exit 1
}

# === DOWNLOAD A FILE FROM GITHUB ===
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

# === BACKUP ORIGINAL mail.cgi ===
backup_mail_cgi() {
  local target="/srv/web/ipfire/cgi-bin/mail.cgi"
  if [[ -f "$target" && ! -f "$MAIL_CGI_ORIG" ]]; then
    dry cp -f "$target" "$MAIL_CGI_ORIG"
    dry chown root:root "$MAIL_CGI_ORIG"
    dry chmod 755 "$MAIL_CGI_ORIG"
    log "Backed up original mail.cgi → $MAIL_CGI_ORIG"
  else
    [[ -f "$target" ]] && warn "mail.cgi already backed up – skipping"
  fi
}

# === RESTORE ORIGINAL mail.cgi ===
restore_mail_cgi() {
  local target="/srv/web/ipfire/cgi-bin/mail.cgi"
  if [[ -f "$MAIL_CGI_ORIG" ]]; then
    dry cp -f "$MAIL_CGI_ORIG" "$target"
    dry chown root:root "$target"
    dry chmod 755 "$target"
    log "Restored original mail.cgi from backup"
  else
    warn "No mail.cgi backup found – attempting to restore default"
    if [[ -f "/srv/web/ipfire/cgi-bin/mail.cgi-core197" ]]; then
      dry cp -f "/srv/web/ipfire/cgi-bin/mail.cgi-core197" "$target"
      dry chown root:root "$target"
      dry chmod 755 "$target"
      log "Restored mail.cgi from core backup (mail.cgi-core197)"
    else
      warn "No core backup found – manual restore of mail.cgi required"
    fi
  fi
}

# === INSTALLATION ROUTINE ===
install_mode() {
  log "Starting installation..."
  backup_mail_cgi

  for dir in "${OUR_DIRS[@]}"; do
    [[ ! -d "$dir" ]] && dry mkdir -p "$dir" && log "Created: $dir"
  done

  dry chown nobody:nobody "$GPGDIR"
  dry chmod 700 "$GPGDIR"
  log "GPGDIR: mode 700, owner nobody:nobody — key import fix"
  dry chown nobody:nobody "$LOGDIR" "$CONFDIR" "/var/ipfire/encryption/logging" 2>/dev/null || true
  dry chmod 750 "$LOGDIR" "$CONFDIR"
  dry chmod 755 "/var/ipfire/encryption/logging"

  if ! ls "$GPGDIR"/pubring.* >/dev/null 2>&1 && ! ls "$GPGDIR"/secring.* >/dev/null 2>&1; then
    log "Initializing GPG keyring..."
    dry su -s /bin/sh nobody -c "/usr/bin/gpg --homedir '$GPGDIR' --list-keys >/dev/null 2>&1" || true
  fi

  if [[ -d "$GPGDIR" ]]; then
    dry chown -R nobody:nobody "$GPGDIR"
    dry find "$GPGDIR" -type f -exec chmod 600 {} \;
    log "Fixed GPG keyring permissions"
  fi

  # === NO FROM in encryption.conf – dispatcher reads SENDER from mail.conf ===
  if [[ ! -f "$CONFIG_FILE" ]]; then
    dry tee "$CONFIG_FILE" > /dev/null << 'EOF'
GPGDIR=/var/ipfire/encryption/gpg/keys
TRUSTMODEL=always
ENCRYPT=off
DEBUG=off
LOG_LEVEL=2
EOF
    dry chown root:nobody "$CONFIG_FILE"
    dry chmod 660 "$CONFIG_FILE"
    log "Created encryption.conf (FROM handled by dispatcher via mail.conf)"
  fi

  for repo_path in "${!INSTALL_FILES[@]}"; do
    dest="${INSTALL_FILES[$repo_path]}"
    download_file "$repo_path" "$dest"
  done

  # === SECURE ALTERNATIVES SETUP ===
  if [[ ! -f "$SENDMAIL_DMA_BACKUP" ]] && [[ -L "$SENDMAIL_DMA" ]]; then
    dry cp -a "$SENDMAIL_DMA" "$SENDMAIL_DMA_BACKUP"
    log "Backed up original sendmail.dma → $SENDMAIL_DMA_BACKUP"
  fi

  if [[ ! -x "$DMA_BINARY" ]]; then
    if [[ -f "$SENDMAIL_DMA_BACKUP" ]]; then
      dry ln -sf "$(readlink -f $SENDMAIL_DMA_BACKUP)" "$DMA_BINARY"
      log "Restored real $DMA_BINARY from backup"
    else
      error "Cannot find real dma binary and no backup!"
    fi
  fi

  dry rm -f "$SENDMAIL_DMA"
  dry ln -sf "$DISPATCHER" "$SENDMAIL_DMA"
  log "Symlink: $SENDMAIL_DMA → dispatcher (NO BINARY TOUCH!)"

  dry update-alternatives --install /usr/sbin/sendmail sendmail "$DISPATCHER" 100 || true
  dry update-alternatives --install /usr/sbin/sendmail sendmail "$DMA_BINARY" 20 || true
  dry update-alternatives --set sendmail "$DISPATCHER" >/dev/null 2>&1 || true
  log "update-alternatives: dispatcher (100), dma (20) → dispatcher active"

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

# === UNINSTALL ROUTINE ===
uninstall_mode() {
  local keep_gpg=false
  local full=false
  [[ " $* " == *" --keep-gpg "* ]] && keep_gpg=true
  [[ " $* " == *" --full "* ]] && full=true
  log "Starting uninstallation..."

  if update-alternatives --display sendmail 2>/dev/null | grep -q "$DISPATCHER"; then
    dry update-alternatives --remove sendmail "$DISPATCHER" || true
    log "Removed dispatcher from update-alternatives"
  fi

  if [[ -L "$SENDMAIL_DMA" ]] && [[ $(readlink -f "$SENDMAIL_DMA") == "$DISPATCHER" ]]; then
    dry rm -f "$SENDMAIL_DMA"
    log "Removed dispatcher symlink"
  fi

  if [[ -f "$SENDMAIL_DMA_BACKUP" ]]; then
    dry mv "$SENDMAIL_DMA_BACKUP" "$SENDMAIL_DMA"
    log "Restored: $SENDMAIL_DMA → original"
  elif [[ -x "$DMA_BINARY" ]]; then
    dry ln -sf "$DMA_BINARY" "$SENDMAIL_DMA"
    log "Restored: $SENDMAIL_DMA → $DMA_BINARY"
  fi

  dry update-alternatives --install /usr/sbin/sendmail sendmail "$SENDMAIL_DMA" 20 || true
  dry update-alternatives --set sendmail "$SENDMAIL_DMA" 2>/dev/null || true
  log "Restored: alternatives sendmail → sendmail.dma (priority 20)"

  restore_mail_cgi
  log "Ensured original mail.cgi is restored"

  for repo_path in "${!INSTALL_FILES[@]}"; do
    dest="${INSTALL_FILES[$repo_path]}"
    [[ "$dest" == "/srv/web/ipfire/cgi-bin/mail.cgi" ]] && continue
    [[ -f "$dest" ]] && dry rm -f "$dest" && log "Removed: $dest"
  done

  if [[ -f "$CONFIG_FILE" ]] && ! grep -q "^GPG_KEY=\|DEBUG=on" "$CONFIG_FILE"; then
    dry rm -f "$CONFIG_FILE"
    log "Removed default config"
  fi

  if ! $keep_gpg || $full; then
    for dir in "${OUR_DIRS[@]}"; do
      [[ -d "$dir" ]] && dry rm -rf "$dir" && log "Removed: $dir"
    done
    [[ -f "$MAIL_CGI_ORIG" ]] && dry rm -f "$MAIL_CGI_ORIG" && log "Removed mail.cgi backup"
  fi

  log "Uninstallation completed. IPFire mail system fully restored to original state."
}

# === MAIN EXECUTION ===
main() {
  mkdir -p "$BACKUP_DIR"
  touch "$LOG_FILE"
  case "${1:-}" in
    ""|--help|-h) usage ;;
    install) install_mode ;;
    uninstall) shift; uninstall_mode "$@" ;;
    *) error "Invalid command"; usage ;;
  esac
}

main "$@"
exit 0