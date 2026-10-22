# Deploying Fediverse Verify

Ansible for the verifier's own server: Ubuntu (tested target: OVH Public Cloud, Ubuntu 24.04), rootless Docker, Caddy with automatic TLS, and all data on an encrypted volume whose passphrase you enter after every reboot.

It runs on its **own server, never on a Mastodon host**: the keys that sign proofs must not be reachable from a compromised Mastodon instance.

## What it sets up

| Part | What |
|---|---|
| `base` | Security updates, firewall (22/80/443 only), SSH keys only, fail2ban, compressed-RAM swap and no core dumps (so decrypted memory never lands on the plain disk) |
| `encrypted_storage` | A LUKS volume (a file on the root disk, or an attached volume) holding everything: the verifier's database and keys, Docker's own storage. Asks for the passphrase at boot |
| `rootless_docker` | Docker for an unprivileged `verifier` user whose home is on the encrypted volume |
| `verifier` | Fediverse Verify built from this repository at `verifier_version` (so the page footer links the exact commit that runs), plus what the chosen wallet types need: the test wallet apps, the EU reference verifier endpoint, or the swiyu verifier and its database |
| `caddy` | HTTPS for each site. Only wallet-facing paths of the EU (`/wallet/…`) and Swiss (`/oid4vp/…`) components are public; their management APIs stay private. No access logs |

The four shared roles are copies of those in `mastodon-ops`; keep the copies in sync.

## Before you start

- A fresh Ubuntu server with your SSH key for `ubuntu`, and DNS names pointing at it: `verify.example.org`, plus `wallet.…` (test wallets), `eudi.…` or `swiyu.…` for the wallet types you enable.
- On your machine: Ansible, and `ansible-galaxy collection install -r requirements.yml`.

## First deploy

```sh
cd deploy
cp inventory/hosts.example.yml inventory/hosts.yml          # fill in; git-ignored
mkdir -p inventory/group_vars/verifier
scripts/generate-secrets.sh > inventory/group_vars/verifier/vault.yml
openssl rand -base64 32 > .vault-password && chmod 600 .vault-password
ansible-vault encrypt inventory/group_vars/verifier/vault.yml
ansible-playbook playbooks/site.yml
```

`hosts.yml`, the vault and `.vault-password` are git-ignored: this repository is public. Keep copies of all three somewhere safe (a password manager). **The vault is the backup of the verifier's keys**: if they're lost, every proof already published stops verifying.

Already running a verifier elsewhere? Put its `signing-key.pem` and `actor-ed25519.pem` in the vault instead of new ones. The deploy installs keys only on a server that has none, and stops if the server's keys differ from the vault's.

## After a reboot

The data stays locked until you give the passphrase. Either:

```sh
ansible-playbook playbooks/unlock.yml                        # uses the vault
# or answer the prompt yourself:
ssh -t ubuntu@verify.example.org sudo systemd-tty-ask-password-agent
```

## Updating

Change `verifier_version` (or leave `main`) and run `playbooks/site.yml` again. It rebuilds when the source changed and restarts only what changed.

## Backups

On purpose, **none of the database**: removing a proof must really erase it, and a backup would keep it. Users re-verify if the server is lost. What must survive is the keys, and they're in your vault. The swiyu DID keys (from registration) live outside this server too; see [swiyu-registration.md](swiyu-registration.md).

## Wallet types

Set `verifier_identity_providers`:

| Value | Needs |
|---|---|
| `mock`, `mock-ch` | Nothing; a public demo with fake ID apps. Proofs are test proofs and never earn a badge |
| `eudi` | Registration as an EU wallet relying party (not open yet; EU rules apply from 24 December 2026), then the endpoint's access certificate. Not yet automated here |
| `swiyu` | Registration with swiyu ([swiyu-registration.md](swiyu-registration.md)), then the DID settings and `vault_swiyu_signing_key`. Until the real e-ID launches, only Beta-IDs (test proofs) |

Test and real types can't be mixed.
