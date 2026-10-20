"""HTTP app: verify flow, public proof pages, JWKS, and revocation."""

from __future__ import annotations

import base64
import io
import json
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path

import httpx
import jwt
import segno
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .attestation import Signer, build_claims
from . import buildinfo
from .countries import NAMES as COUNTRY_NAMES, issuer_label
from .binding import BoundAccount
from .binding.linkback import LinkBackBinding
from .binding.mastodon import Authorization, BindingError, MastodonBinding
from .config import Settings
from .identity import IdentityError, IdentityProvider, WalletRequest
from .identity.eudi import EudiProvider
from .identity.mock import MockProvider
from .net import UnsafeHostError
from .store import SCHEMA, Proof, Store

LEVEL_PATH = {"person": "u", "legal_name": "n"}
PATH_LEVEL = {v: k for k, v in LEVEL_PATH.items()}
FLOW_TTL = 30 * 60
PENDING_TTL = 24 * 60 * 60        # unconfirmed link-back proofs are deleted after this
CHECK_INTERVAL = 5                # seconds between link-back checks of one proof
BINDINGS = ("link-back", "mastodon-sign-in")


@dataclass
class Flow:
    purpose: str                                  # "verify" or "revoke"
    level: str = "legal_name"
    binding: str = "mastodon-sign-in"
    include_age: bool = False                     # the person asked to also show "18+"
    auth: Authorization | None = None
    account: BoundAccount | None = None
    wallet: WalletRequest | None = None
    csrf: str = field(default_factory=lambda: secrets.token_urlsafe(16))
    created: float = field(default_factory=time.time)


def new_removal_code() -> str:
    raw = base64.b32encode(secrets.token_bytes(15)).decode()       # 24 chars, 120 bits
    return "-".join(raw[i:i + 4] for i in range(0, len(raw), 4))


def create_app(settings: Settings, http: httpx.AsyncClient | None = None) -> FastAPI:
    http = http or httpx.AsyncClient(timeout=10, follow_redirects=False,
                                     headers={"User-Agent": f"fediverse-verify/0.1 (+{settings.public_url})"})
    store = Store(settings.data_dir / "verifier.sqlite3")
    signer = Signer.load_or_create(settings.data_dir / "signing-key.pem")
    binding = MastodonBinding(http, store, app_name=settings.app_name, website=settings.public_url,
                              redirect_uri=f"{settings.public_url}/auth/mastodon/callback",
                              allow_private_hosts=settings.allow_private_hosts)
    linkback = LinkBackBinding(http, allow_private_hosts=settings.allow_private_hosts)
    last_check: dict[str, float] = {}
    provider: IdentityProvider
    if settings.identity_provider == "mock":
        provider = MockProvider()
    elif settings.identity_provider == "eudi":
        provider = EudiProvider(http, settings.eudi_endpoint, settings.eudi_wallet_scheme)
    else:
        raise ValueError(f"unknown identity provider {settings.identity_provider!r}")

    flows: dict[str, Flow] = {}
    templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
    templates.env.globals.update(settings=settings, mock=settings.identity_provider == "mock",
                                 build=buildinfo.detect(settings.source_url))
    templates.env.filters["date"] = lambda ts: time.strftime("%Y-%m-%d", time.gmtime(ts))
    templates.env.globals.update(issuer_label=issuer_label, country_names=COUNTRY_NAMES)
    templates.env.globals.update(signing_key_id=signer.kid)

    def proof_label(proof: Proof, sep: str = " · ") -> str:
        """'Verified name', 'Verified person', with '· 18+' when shown."""
        base = "Verified name" if proof.verification_level == "legal_name" else "Verified person"
        return base + (f"{sep}18+" if proof.age_over_18 else "")
    templates.env.globals.update(proof_label=proof_label)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        await http.aclose()

    app = FastAPI(title=settings.app_name, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
    app.add_middleware(SessionMiddleware, secret_key=settings.session_secret, session_cookie="fv_session",
                       same_site="lax", https_only=settings.public_url.startswith("https://"))

    # ---- helpers ----
    def render(request: Request, name: str, status: int = 200, **ctx) -> HTMLResponse:
        return templates.TemplateResponse(request, name, ctx, status_code=status)

    def message(request: Request, title: str, text: str, status: int = 400) -> HTMLResponse:
        return render(request, "message.html", status, title=title, text=text)

    def start_flow(request: Request, flow: Flow) -> None:
        now = time.time()
        for key in [k for k, f in flows.items() if now - f.created > FLOW_TTL]:
            flows.pop(key, None)
        flow_id = secrets.token_urlsafe(16)
        flows[flow_id] = flow
        request.session["flow"] = flow_id

    def current_flow(request: Request) -> Flow:
        flow = flows.get(request.session.get("flow", ""))
        if flow is None or time.time() - flow.created > FLOW_TTL:
            raise HTTPException(status_code=400, detail="Your session expired. Please start again.")
        return flow

    def end_flow(request: Request) -> None:
        flows.pop(request.session.pop("flow", ""), None)

    def proof_url(proof: Proof) -> str:
        return f"{settings.public_url}/{LEVEL_PATH[proof.verification_level]}/{proof.id}"

    def check_csrf(flow: Flow, token: str) -> None:
        if not secrets.compare_digest(flow.csrf, token):
            raise HTTPException(status_code=400, detail="Invalid form submission.")

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        if exc.status_code == 404:
            return message(request, "Not found", "There is no proof here. It may have been revoked.", 404)
        return message(request, "Something went wrong", str(exc.detail), exc.status_code)

    # ---- verify flow ----
    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        return render(request, "index.html")

    async def begin_sign_in(request: Request, handle: str, purpose: str, level: str = "legal_name",
                            include_age: bool = False):
        try:
            auth = await binding.authorize(handle)
        except (BindingError, UnsafeHostError) as e:
            return message(request, "Can't sign in", str(e))
        except httpx.HTTPError:
            return message(request, "Can't reach your server", "Check the handle and try again.", 502)
        start_flow(request, Flow(purpose=purpose, level=level, auth=auth, include_age=include_age))
        return RedirectResponse(auth.url, status_code=303)

    @app.post("/verify")
    async def verify_start(request: Request, handle: str = Form(...), level: str = Form("legal_name"),
                           binding_method: str = Form("link-back", alias="binding"),
                           show_age: str = Form("")):
        include_age = show_age == "yes"
        if level not in LEVEL_PATH or binding_method not in BINDINGS:
            raise HTTPException(status_code=400, detail="Unknown option.")
        if binding_method == "mastodon-sign-in":
            return await begin_sign_in(request, handle, "verify", level, include_age)
        try:
            account = await linkback.resolve(handle)
        except (BindingError, UnsafeHostError) as e:
            return message(request, "Can't find that account", str(e))
        except httpx.HTTPError:
            return message(request, "Can't reach your server", "Check the handle and try again.", 502)
        flow = Flow(purpose="verify", level=level, binding="link-back", account=account, include_age=include_age)
        start_flow(request, flow)
        return await begin_wallet(request, flow)

    async def begin_wallet(request: Request, flow: Flow):
        try:
            flow.wallet = await provider.begin(flow.level, flow.include_age)
        except (IdentityError, httpx.HTTPError) as e:
            end_flow(request)
            return message(request, "Wallet unavailable", str(e) or "Please try again later.", 502)
        return RedirectResponse("/wallet", status_code=303)

    @app.get("/auth/mastodon/callback")
    async def mastodon_callback(request: Request, code: str = "", state: str = "", error: str = ""):
        flow = current_flow(request)
        if error or not code or flow.auth is None or not secrets.compare_digest(state, flow.auth.state):
            end_flow(request)
            return message(request, "Sign-in cancelled", "Nothing was changed.")
        try:
            flow.account = await binding.complete(flow.auth.host, code, flow.auth.code_verifier)
        except (BindingError, httpx.HTTPError) as e:
            end_flow(request)
            return message(request, "Sign-in failed", str(e) or "Please try again.", 502)
        flow.auth = None
        if flow.purpose == "revoke":
            return RedirectResponse("/revoke/account", status_code=303)
        return await begin_wallet(request, flow)

    @app.get("/wallet", response_class=HTMLResponse)
    async def wallet_page(request: Request):
        flow = current_flow(request)
        if flow.account is None or flow.wallet is None:
            raise HTTPException(status_code=400, detail="Please start again.")
        qr_svg = ""
        if flow.wallet.kind == "qr":
            buf = io.BytesIO()
            segno.make(flow.wallet.wallet_url, error="m").save(buf, kind="svg", scale=5, xmldecl=False)
            qr_svg = buf.getvalue().decode()
        return render(request, "wallet.html", flow=flow, qr_svg=qr_svg)

    @app.post("/wallet/mock")
    async def wallet_mock_submit(request: Request, csrf: str = Form(...), given_name: str = Form(""),
                                 family_name: str = Form(""), issuing_country: str = Form("IT"),
                                 issuing_authority: str = Form(""), over_18: str = Form("")):
        if not isinstance(provider, MockProvider):
            raise HTTPException(status_code=404)
        flow = current_flow(request)
        check_csrf(flow, csrf)
        if flow.wallet is None:
            raise HTTPException(status_code=400, detail="Please start again.")
        provider.submit(flow.wallet.handle, given_name.strip(), family_name.strip(),
                        issuing_country.strip()[:2], issuing_authority.strip()[:100],
                        age_over_18=flow.include_age and over_18 == "yes")
        return RedirectResponse("/wallet/done", status_code=303)

    @app.get("/wallet/status")
    async def wallet_status(request: Request):
        flow = current_flow(request)
        if flow.wallet is None:
            return JSONResponse({"state": "error"})
        try:
            result = await provider.result(flow.wallet)
        except (IdentityError, httpx.HTTPError):
            return JSONResponse({"state": "error"})
        if result is None:
            return JSONResponse({"state": "pending"})
        return await _issue(request, flow, result, as_json=True)

    @app.get("/wallet/done")
    async def wallet_done(request: Request):
        flow = current_flow(request)
        if flow.wallet is None:
            raise HTTPException(status_code=400, detail="Please start again.")
        try:
            result = await provider.result(flow.wallet)
        except IdentityError as e:
            end_flow(request)
            return message(request, "Verification failed", str(e))
        if result is None:
            return RedirectResponse("/wallet", status_code=303)
        return await _issue(request, flow, result)

    async def _issue(request: Request, flow: Flow, result, as_json: bool = False):
        account = flow.account
        assert account is not None
        name = result.full_name if flow.level == "legal_name" else None
        if flow.level == "legal_name" and not name:
            end_flow(request)
            return message(request, "Verification failed", "No name was provided.")
        proof = Proof(id=secrets.token_urlsafe(12), verification_level=flow.level, subject_uri=account.subject_uri,
                      account_profile_url=account.profile_url, handle=account.handle, name=name,
                      identity_check_method=result.method, attestation="", created_at=int(time.time()),
                      account_ownership_check=flow.binding,
                      issuing_country=result.issuing_country, issuing_authority=result.issuing_authority,
                      age_over_18=True if (flow.include_age and result.age_over_18) else None)
        if flow.binding == "link-back":
            # Not live until the account links to it; see /check.
            proof = replace(proof, status="pending", expires_at=proof.created_at + PENDING_TTL)
        else:
            proof = replace(proof, attestation=sign(proof))
        code = new_removal_code()
        store.add_proof(proof, code)
        end_flow(request)
        request.session["issued"] = {"id": proof.id, "code": code,
                                     "age_not_confirmed": flow.include_age and not proof.age_over_18}
        if as_json:
            return JSONResponse({"state": "done", "next": "/issued"})
        return RedirectResponse("/issued", status_code=303)

    @app.get("/issued", response_class=HTMLResponse)
    async def issued(request: Request):
        info = request.session.pop("issued", None)        # shown once: the code is never shown again
        proof = store.get_proof(info["id"]) if info else None
        if proof is None:
            return RedirectResponse("/", status_code=303)
        return render(request, "issued.html", proof=proof, url=proof_url(proof), code=info["code"],
                      age_not_confirmed=info.get("age_not_confirmed", False))

    def sign(proof: Proof) -> str:
        claims = build_claims(issuer=settings.public_url, proof_id=proof.id, subject_uri=proof.subject_uri,
                              profile_url=proof.account_profile_url, level=proof.verification_level, method=proof.identity_check_method,
                              name=proof.name, binding=proof.account_ownership_check, issuing_country=proof.issuing_country,
                              issuing_authority=proof.issuing_authority, age_over_18=proof.age_over_18)
        return signer.sign(claims)

    # ---- link-back confirmation (public: anyone may trigger a check, it only reads) ----
    @app.post("/check/{proof_id}")
    async def check_link_back(request: Request, proof_id: str):
        proof = store.get_proof(proof_id)
        if proof is None:
            raise HTTPException(status_code=404)
        wants_json = "application/json" in request.headers.get("accept", "")
        if proof.status == "pending" and time.time() - last_check.get(proof.id, 0) >= CHECK_INTERVAL:
            last_check[proof.id] = time.time()
            account = BoundAccount(subject_uri=proof.subject_uri, profile_url=proof.account_profile_url, handle=proof.handle)
            try:
                linked = await linkback.links_to(account, proof_url(proof))
            except (httpx.HTTPError, UnsafeHostError, BindingError):
                linked = False
            if linked:
                now = int(time.time())
                store.activate(proof.id, sign(replace(proof, created_at=now)), now)
                last_check.pop(proof.id, None)
                proof = store.get_proof(proof.id) or proof
        if wants_json:
            return JSONResponse({"status": proof.status})
        return RedirectResponse(proof_url(proof) + ("?checked=1" if proof.status == "pending" else ""),
                                status_code=303)

    @app.get("/about", response_class=HTMLResponse)
    async def about(request: Request):
        from . import transparency           # imported lazily: it inspects this module
        build = templates.env.globals["build"]
        return render(request, "about.html", code=transparency.build_links(build), schema=SCHEMA.strip(),
                      pending_hours=PENDING_TTL // 3600, flow_minutes=FLOW_TTL // 60)

    # ---- revocation (standalone; see docs/overview.md#revocation-and-erasure) ----
    @app.get("/revoke", response_class=HTMLResponse)
    async def revoke_page(request: Request):
        return render(request, "revoke.html")

    @app.post("/revoke/code", response_class=HTMLResponse)
    async def revoke_with_code(request: Request, code: str = Form(...)):
        proof = store.delete_by_removal_code(code)
        if proof is None:
            return message(request, "Code not recognised", "Check the code and try again. "
                           "If the proof was already revoked, there is nothing left to remove.", 404)
        return render(request, "revoked.html", proofs=[proof])

    @app.post("/revoke/sign-in")
    async def revoke_sign_in(request: Request, handle: str = Form(...)):
        return await begin_sign_in(request, handle, "revoke")

    @app.get("/revoke/account", response_class=HTMLResponse)
    async def revoke_account(request: Request):
        flow = current_flow(request)
        if flow.purpose != "revoke" or flow.account is None:
            raise HTTPException(status_code=400, detail="Please sign in again.")
        return render(request, "revoke_account.html", flow=flow,
                      proofs=store.proofs_for_subject(flow.account.subject_uri),
                      url_for_proof=proof_url)

    @app.post("/revoke/account", response_class=HTMLResponse)
    async def revoke_account_submit(request: Request, csrf: str = Form(...)):
        flow = current_flow(request)
        if flow.purpose != "revoke" or flow.account is None:
            raise HTTPException(status_code=400, detail="Please sign in again.")
        check_csrf(flow, csrf)
        proofs = store.proofs_for_subject(flow.account.subject_uri)
        for proof in proofs:
            store.delete_proof(proof.id)
        end_flow(request)
        return render(request, "revoked.html", proofs=proofs)

    @app.get("/.well-known/jwks.json")
    async def jwks():
        return JSONResponse(signer.jwks(), headers={"Cache-Control": "public, max-age=3600"})

    # ---- public proof pages (registered last: their catch-all paths would shadow other routes) ----
    def load_proof(prefix: str, proof_id: str) -> Proof:
        proof = store.get_proof(proof_id)
        if proof is None or PATH_LEVEL.get(prefix) != proof.verification_level:
            raise HTTPException(status_code=404)
        return proof

    @app.get("/{prefix}/{proof_id}.jwt", response_class=PlainTextResponse)
    async def proof_jwt(prefix: str, proof_id: str):
        proof = load_proof(prefix, proof_id)
        if proof.status != "active":
            raise HTTPException(status_code=404)
        return PlainTextResponse(proof.attestation, media_type="application/jwt",
                                 headers={"X-Robots-Tag": "noindex"})

    @app.get("/{prefix}/{proof_id}", response_class=HTMLResponse)
    async def proof_page(request: Request, prefix: str, proof_id: str, checked: str = ""):
        if prefix not in PATH_LEVEL:
            raise HTTPException(status_code=404)
        proof = load_proof(prefix, proof_id)
        claims_json = ""
        if proof.status == "active":
            claims = jwt.decode(proof.attestation, options={"verify_signature": False})   # our own token
            claims_json = json.dumps(claims, indent=2, ensure_ascii=False)
        response = render(request, "proof.html", proof=proof, url=proof_url(proof), checked=bool(checked),
                          claims_json=claims_json,
                          verified_on=time.strftime("%Y-%m-%d", time.gmtime(proof.created_at)))
        response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
        return response

    return app


def main() -> FastAPI:
    """Entry point for `uvicorn --factory fediverse_verify.app:main`."""
    return create_app(Settings.from_env())
