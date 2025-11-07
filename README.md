# IPFire-Encryption-PKI
Central Key Management for IPFire – GPG, X.509

---

## Current Features

**Currently highly experimental, please use testing systems for this**

- GPG Key Management in the Web UI: Upload, View, Delete, Set Default, Test
- Encrypted Emails via `sendmail.gpg`
- Masquerade Support (custom sender address)
- Test Mail (encrypted or unencrypted)
- 1-Click Installation via `curl` from GitHub
- Safe Uninstallation with `--keep-gpg` and `--dry-run` options

---

## Future: Full PKI (Planned)

> Note: X.509 and other PKI features are in planning – not yet implemented.

| Module                | Status   |
|-----------------------|----------|
| GPG (Mail Encryption) | Done     |
| X.509 CA              | Planned  |
| OpenVPN Certificates  | Planned  |
| IPSec Keys            | Planned  |
| Central Key Dashboard | `encryption.cgi` as foundation |

---

## Quick Start (script Install)

```bash
curl -sL https://raw.githubusercontent.com/ummeegge/IPFire-Encryption-PKI/main/install.sh | bash -s -- --help

