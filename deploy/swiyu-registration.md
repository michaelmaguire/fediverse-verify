# Registering with swiyu (Swiss e-ID)

How to register Fediverse Verify as a verifier on the swiyu trust infrastructure, so the Swiss e-ID can be checked with the federal generic verifier (`swiyu-verifier` in `docker-compose.yml`, profile `swiyu`).

Status (October 2026): only the **Sandbox** (also called Public Beta) is open. It has no real e-IDs, only the **Beta-ID**, whose holder types in any details they like ("not a proof of identification"). The real e-ID was due on 1 December 2026; that date was postponed in June 2026 with no new date announced. Registering now lets us test the full path with the real swiyu app; proofs made this way are test proofs (`swiyu-beta-id`, `"test": true`) and never earn a badge.

Sources: swiyu cookbooks [Onboarding the Base & Trust Registry](https://swiyu-admin-ch.github.io/cookbooks/onboarding-base-and-trust-registry/), [Generic Verifier](https://swiyu-admin-ch.github.io/cookbooks/onboarding-generic-verifier/), [How to use Beta-ID](https://swiyu-admin-ch.github.io/cookbooks/how-to-use-beta-id/), and the [swiyu-verifier README](https://github.com/swiyu-admin-ch/swiyu-verifier). Checked 2026-10-22; the Sandbox changes often, so re-read them before starting.

## Before you start: decisions

| Decision | Options | Notes |
|---|---|---|
| **Who registers** | You as an individual, or an organisation | The Sandbox is open to "organisations and individuals", free, with no limit on participants. No Swiss company number (UID) is required; the trust protocol lists it only as an optional registry ID. The name you give appears to wallet users |
| **Public HTTPS address for the Swiss verifier** | e.g. `https://swiyu.verify.example.org` on the verifier's own server | Wallets (phones) must reach its `/oid4vp/api` endpoints over HTTPS. Its management API must stay private (only Fediverse Verify talks to it). The local test stack is localhost-only, so a real phone can't reach it |
| **Where keys and tokens live** | The verifier server's encrypted data disk, plus an offline backup | The DID keys are the verifier's Swiss identity: losing them means a new DID and new registration; leaking them lets someone act as us |
| **Purpose statements: manual or automatic** | Submit the four statements once by hand (below), or let `swiyu-verifier` register them on the fly (`SWIYU_TMS_*` settings, marked "testing purposes only") | Manual is simpler and keeps the trust-registry credentials out of the running service |

## What you'll collect

Keep these in a password manager or the encrypted disk; never commit them.

| Item | From | Used by |
|---|---|---|
| ePortal account | Step 1 | You, to manage the registration |
| `PARTNER_ID` (business partner UUID) | Step 1 (top right of the API self-service portal) | API calls |
| API application key, secret, access token (24 h), refresh token (7 days), for each of identifier, status and trust APIs | Step 2 | API calls; new ones can be generated any time |
| DID log `did.jsonl` and the `.didtoolbox/` key files | Step 3 | Updating the DID, proofs of possession, and `SWIYU_SIGNING_KEY` |
| The verifier DID (`did:webvh:…`) and its verification method (`…#auth-key-01` or similar) | Step 3 | `SWIYU_VERIFIER_DID`, `SWIYU_DID_VERIFICATION_METHOD` |

## Steps

### 1. Account and business partner

1. Open the [swiyu Service Portal](https://portal.trust-infra.swiyu-int.admin.ch) and sign in with an ePortal account (create one if needed).
2. Register the business partner: name and email. Accept the terms (they're at the bottom of the page).

### 2. Subscribe to the three APIs

In the [API self-service portal](https://selfservice.api.admin.ch/api-selfservice/) (open **APIs** after signing in), with our business partner selected:

1. Create one application for the verifier (swiyu suggests one per service).
2. Subscribe it to `swiyucorebusiness_identifier`, `swiyucorebusiness_status` and `swiyucorebusiness_trust`. After adding a subscription, refresh the tokens so they include it.
3. Save the key, secret and tokens; they're shown once.

### 3. Create the verifier DID

Needs Java and the [DID Toolbox](https://github.com/swiyu-admin-ch/didtoolbox-java/releases/latest). Run this in a private working directory on the encrypted disk.

```sh
# 3.1 Find the DID space provisioned for us (status NOT_INITIALIZED)
curl "https://identifier-reg-api.trust-infra.swiyu-int.admin.ch/api/v1/identifier/business-entities/$PARTNER_ID/identifier/" \
  -H "Authorization: Bearer $SWIYU_IDENTIFIER_REGISTRY_ACCESS_TOKEN"
# save its id as ENTRY_ID and identifierRegistryUrl as REGISTRY_URL

# 3.2 Generate the DID log; keys are written to .didtoolbox/
java -jar didtoolbox.jar create --identifier-registry-url "$REGISTRY_URL" > did.jsonl

# 3.3 Publish it
curl -X PUT "https://identifier-reg-api.trust-infra.swiyu-int.admin.ch/api/v1/identifier/business-entities/$PARTNER_ID/identifier-entries/$ENTRY_ID" \
  -H "Authorization: Bearer $SWIYU_IDENTIFIER_REGISTRY_ACCESS_TOKEN" \
  -H "Content-Type: application/jsonl+json" --data-binary @did.jsonl
```

Note the DID (in `did.jsonl`) and the IDs of its keys. Check which key the verifier should sign with: `SWIYU_SIGNING_KEY` must be the EC private key whose public key is `SWIYU_DID_VERIFICATION_METHOD` (swiyu's example uses the `#auth-key-01` key).

### 4. Trust registry: prove we hold the key

1. In the Service Portal, open the business partner and press **Start profile verification**; follow it until it asks for a proof of possession.
2. Fetch the challenge, sign it, submit it (the proof is valid for 24 hours):

```sh
curl "https://trust-reg-api.trust-infra.swiyu-int.admin.ch/api/v1/trust/trust-onboarding-submission/proof-of-possessions" \
  -H "Authorization: Bearer $SWIYU_TRUST_REGISTRY_ACCESS_TOKEN"            # gives DID and NONCE

java -jar didtoolbox.jar create-pop -d did.jsonl -k "$DID#assert-key-01" -s .didtoolbox/assert-key-01 -n "$NONCE"
# save the output as POP_JWT

curl -X POST "https://trust-reg-api.trust-infra.swiyu-int.admin.ch/api/v1/trust/trust-onboarding-submission/proof-of-possessions" \
  -H "Authorization: Bearer $SWIYU_TRUST_REGISTRY_ACCESS_TOKEN" -H "Content-Type: application/json" \
  -d "{\"proofOfPossessions\": [\"$POP_JWT\"]}"
```

### 5. Publish our purpose statements (vqPS)

swiyu requires a public statement for every distinct query a verifier sends, so wallet users can see what we ask for and why before sharing anything. We send four (each level, with and without 18+). Generate them from the code that builds the queries, so they always match:

```sh
# from the fediverse-verify checkout; add the real e-ID type later as a second argument
python -m fediverse_verify.identity.swiyu "$DID" > vqps.jsonl

while read -r body; do
  curl -X POST "https://trust-reg-api.trust-infra.swiyu-int.admin.ch/api/v1/trust/vqps-submissions" \
    -H "Authorization: Bearer $SWIYU_TRUST_REGISTRY_ACCESS_TOKEN" -H "Content-Type: application/json" \
    -d "$body"
done < vqps.jsonl
```

Each should answer `PUBLICATION_SUCCEEDED`. On a `504`, check it with `GET …/vqps-submissions/<id>`. If a purpose text or query ever changes, `tests/test_swiyu.py` shows it and new statements must be submitted.

### 6. Run the Swiss verifier and switch it on

On the verifier server, next to Fediverse Verify (`docker-compose.yml`, profile `swiyu`):

```sh
SWIYU_EXTERNAL_URL=https://swiyu.verify.example.org   # public HTTPS, proxied to swiyu-verifier:8080 /oid4vp only
SWIYU_VERIFIER_DID=did:webvh:…
SWIYU_DID_VERIFICATION_METHOD=did:webvh:…#auth-key-01
SWIYU_SIGNING_KEY="$(cat .didtoolbox/auth-key-01)"   # the EC key matching the method above
SWIYU_DB_PASSWORD=$(openssl rand -hex 24)
VERIFIER_IDENTITY_PROVIDERS=swiyu                    # or eudi,swiyu
# Sandbox Beta-ID issuer (from swiyu's 4 Sept 2026 announcement; check it's still current)
VERIFIER_SWIYU_ISSUER_DIDS=did:webvh:QmdPxnNc9MzGYZ6qcHuvi8YpDVYWW7mmefnCTPcKapNEL5:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:5f8a3c95-1772-4ebf-ada0-c88bafb258e1
# VERIFIER_SWIYU_VCT_VALUES left empty: Beta-ID, test proofs only
docker compose --profile swiyu up -d
```

The proxy must expose only `/oid4vp/…` publicly, never `/management/…`.

### 7. Test

1. On a phone, install the swiyu app and get a Beta-ID from the [Beta Credential Service](https://www.bcs.admin.ch/bcs-web) using made-up details.
2. Verify an account on Fediverse Verify, choosing the Swiss ID app, and scan the QR code.
3. Expect: the swiyu app shows our name and purpose; the proof page says **TEST PROOF … swiyu Beta-ID**; its signed copy (`<proof URL>.json`) has `"identity_check_method": "swiyu-beta-id"` and `"test": true`; Mastodon shows no badge.

## When the real e-ID launches

- Set `VERIFIER_SWIYU_VCT_VALUES` to the e-ID's credential type and `VERIFIER_SWIYU_ISSUER_DIDS` to fedpol's issuer DID, both from the production trust registry.
- Register again on the **production** infrastructure (the Sandbox is a separate environment) and submit the purpose statements there, with the e-ID type: `python -m fediverse_verify.identity.swiyu "$DID" "<e-ID type>"`.
- swiyu plans to add issuer and verifier "legitimacy" statements per credential type at go-live; check whether verifiers of the e-ID will need one.
- Proofs then carry `swiyu-eid` and count as real.
