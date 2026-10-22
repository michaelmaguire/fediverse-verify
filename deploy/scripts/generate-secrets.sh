#!/usr/bin/env bash
# Print a new vault: LUKS passphrase, session secret and the verifier's two keys.
# Usage: scripts/generate-secrets.sh > inventory/group_vars/verifier/vault.yml
# Run once. If the verifier already runs, take its keys from the server instead
# (they sign every published proof): see README.md.
set -euo pipefail
indent() { sed 's/^/  /'; }
cat <<YAML
---
vault_luks_passphrase: "$(openssl rand -base64 32)"
vault_verifier_session_secret: "$(openssl rand -hex 32)"
vault_verifier_signing_key: |
$(openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 | indent)
vault_verifier_actor_key: |
$(openssl genpkey -algorithm ed25519 | indent)
vault_swiyu_db_password: "$(openssl rand -hex 24)"
YAML
