# fediverse-verify

Turns a government digital ID (EU Digital Identity wallet / IT-Wallet) into a signed proof page that Fediverse software can link to. A real person can show that they control an account, optionally with their legal name, without the account's server ever seeing their ID.

Design and decisions: [`docs/overview.md`](https://github.com/michaelmaguire/fediverse-verified/blob/main/docs/overview.md) in the super repo.

## How it works

1. **The user proves they control the account**, by one of two methods:
   - **Link from profile** (default; any Fediverse software): the proof starts *pending* and goes live once the account's public profile links to it. Pending pages carry `rel="me"` but no name or attestation; unconfirmed proofs are deleted after 24 hours. Anyone can trigger a re-check with `POST /check/<id>`.
   - **Sign in with Mastodon** (OAuth, `read:accounts`): live immediately; the token is revoked right after use.
2. **They pick a level:**
   - **Verified name** (recommended): `given_name` + `family_name` are requested and published.
   - **Verified person**: no name; nothing about the person is published beyond the issuer.

   Both levels also request and publish `issuing_country` and `issuing_authority`, so readers see which government vouched.
3. **Their wallet presents the credential** via OpenID4VP (or the mock form in development).
4. **The verifier publishes a proof page** at `/n/<id>` (name) or `/u/<id>` (person) containing:
   - `<link rel="me">` to the exact profile URL, so stock Mastodon shows a green check;
   - a signed attestation (ES256 JWS, `typ: identity-attestation+jwt`), embedded and at `<page>.jwt`, verifiable with `/.well-known/jwks.json`.
5. **The user gets a one-time removal code** to remove the proof later, even without the account.

Signed-copy claims: `iss`, `sub` (ActivityPub actor URI), `iat`, `jti` (registered JWT claims), `account_profile_url`, `verification_level` (`person` | `legal_name`), `identity_check_method` (`eudi-pid` | `mock`), `account_ownership_check` (`link-back` | `mastodon-sign-in`), `issuing_country`, `issuing_authority` (EU PID rulebook names), and `name` (legal_name only; OpenID Connect name). There is no `exp`: proofs last until revoked.

## Data kept

Per proof: account URI, profile URL, handle, level, method, binding, status (pending/active), issuing country and authority, attestation, the name (name level only), and a SHA-256 hash of the revocation code. Also one OAuth app registration per Mastodon server. **Nothing links two proofs to the same person**: no ID numbers, birth dates or document data.

- **Deletion:** SQLite runs with `secure_delete` on, so removed rows are zeroed in the file.
- **Logs:** the container runs uvicorn with `--no-access-log`, so no IPs or proof IDs are logged.
- **EUDI endpoint:** `docker-compose.yml` sets `VERIFIER_MAXAGE` and `VERIFIER_PRESENTATIONS_CLEANUP_MAXAGE` to 10 minutes; its default keeps wallet responses in memory for 10 days.
- **`/about`** describes all of this to users, shows the schema verbatim, and links each claim to the code at the running commit. A test fails if a stored column isn't described there.

## Revocation

`/revoke` deletes everything about a proof, via the revocation code or by signing in with the account (which removes all of that account's proofs). Deleted proofs return 404. The user must also remove the profile field, because their own Mastodon server never re-checks a link that is already verified.

## Develop

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
VERIFIER_SESSION_SECRET=dev .venv/bin/uvicorn --factory fediverse_verify.app:main --reload
```

To test end-to-end with a real Mastodon, use `local/` in the super repo (`./setup.sh`).

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `VERIFIER_PUBLIC_URL` | `http://localhost:8000` | Public base URL (used in proof URLs and as `iss`) |
| `VERIFIER_SESSION_SECRET` | required | Signs the session cookie |
| `VERIFIER_DATA_DIR` | `./data` (`/data` in Docker) | SQLite DB and signing key (`signing-key.pem`, created on first start) |
| `VERIFIER_IDENTITY_PROVIDER` | `mock` | `mock` (development only, proofs marked "mock") or `eudi` |
| `VERIFIER_EUDI_ENDPOINT` | — | Base URL of the EUDI reference verifier endpoint |
| `VERIFIER_ALLOW_PRIVATE_HOSTS` | `false` | Allow account servers on private IPs (local testing only) |
| `VERIFIER_SOURCE_URL` | `https://github.com/michaelmaguire/fediverse-verify` | Linked from every page's footer |
| `VERIFIER_GIT_COMMIT` | from `git`, else unknown | Commit shown in the footer; set by the `GIT_COMMIT` build arg (`<sha>` or `<sha>-dirty`). Only a clean commit is linked. |
| `VERIFIER_OPERATOR_CONTACT` | — | Shown on `/about` for removal requests from people who lost both account and code |
| `VERIFIER_STORAGE_ENCRYPTED` | `false` | Set when the data folder is on an encrypted disk (the `deploy/` recipe does); `/about` says so |
| `VERIFIER_RP_REGISTRAR` | — | Who registered this verifier as a wallet relying party (e.g. `AgID (Italy)`); shown on `/about` |
| `VERIFIER_RP_REGISTER_URL` | — | Link to its entry in the public register. Unset: `/about` says the verifier is not registered |

## Status

- Working and tested: both account-binding methods, mock wallet, both levels, signed proofs, JWKS, revocation (34 tests, plus an end-to-end run against Mastodon 4.7 in `local/`).
- Written but untested against a real wallet: the `eudi` provider.
- Not yet: `deploy/` (Ansible for the verifier's own server); optionally removing the profile field during revocation; in-memory flow state means a single process only.

## License

Copyright 2026 Michael Maguire. Licensed under the [Apache License, Version 2.0](LICENSE).
