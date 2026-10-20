# Test wallets (fake, for development only)

Three pretend ID apps for trying Fediverse Verify without a real wallet. **They are not wallets**: they hold fictional identities and nothing they send is signed. The verifier marks every proof made with them as `mock`.

| App | Imitates | System | Test identities |
|---|---|---|---|
| **IT-Wallet (TEST)** | Italy's wallet in the IO app | EU | Mario Rossi (adult), Giulia Bianchi (under 18) |
| **EUDI Wallet Deutschland (TEST)** | A German EU wallet | EU | Lea Beispiel (adult), Jonas Beispiel (under 18) |
| **swiyu (TEST)** | The Swiss e-ID app | Switzerland | Heidi Muster (adult) |

## How they're used

The verifier behaves as in production: after you pick your ID app, it shows a QR code and an "open it on this device" link. Opening the link here:

1. **EU requests** show an "Open with…" chooser (IT or German app), as a phone does when several wallets can open a link. **Swiss requests** open the swiyu test app directly.
2. The app fetches the request from the verifier and shows a **consent screen**: who is asking, why, and exactly which details, with each test identity's values.
3. **Share** posts that identity's values for the requested details only; **Decline** posts a refusal. Birth dates never leave the app; "over 18" is sent as yes/no.

## Protocol

This is the verifier's own test protocol, not OpenID4VP, which is why the apps live in this repo and change together with `src/fediverse_verify/identity/mock.py`:

- `GET {request_uri}`: `{client_name, client_url, system, purpose, requested_claims, nonce, response_uri, return_url}`
- `POST {response_uri}`: `{nonce, decision: "share" | "decline", claims: {...}}`. The verifier rejects a wrong nonce, unrequested claims, a country outside the system (e.g. a Swiss ID for an EU request), and second answers.

## Run

In the super repo's `local/` environment they're at https://wallet.localhost:8443 (service `test-wallet`). Standalone:

```bash
pip install -r requirements.txt
VERIFIER_ORIGIN=https://verify.localhost:8443 uvicorn app:app --port 8001
```

Only requests from `VERIFIER_ORIGIN` can be opened. To add a test app or identity, add an entry to `APPS` in `app.py`.
