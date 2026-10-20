"""Fake wallet apps for testing Fediverse Verify locally. NOT real wallets.

Three test "apps" (two EU-style, one Swiss-style), each holding fictional test
identities as if a government had already issued them. They open a verifier's
request link, show a consent screen listing exactly what is requested, and post
back the chosen identity's values, or a refusal. Nothing here is signed or real.
"""

from __future__ import annotations

import os
from datetime import date
from urllib.parse import quote, urlparse

import httpx
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

VERIFIER_ORIGIN = os.environ.get("VERIFIER_ORIGIN", "https://verify.localhost:8443").rstrip("/")


def person(given, family, born, country, authority):
    return {"given_name": given, "family_name": family, "birthdate": born,
            "issuing_country": country, "issuing_authority": authority}


APPS = {
    "it": {"name": "IT-Wallet", "tagline": "Test copy of Italy's wallet (in the IO app)", "system": "eu",
           "color": "#0b5ed7", "personas": {
               "mario": person("Mario", "Rossi", "1980-05-23", "IT", "Ministero dell'Interno"),
               "giulia": person("Giulia", "Bianchi", "2011-03-14", "IT", "Ministero dell'Interno")}},
    "de": {"name": "EUDI Wallet Deutschland", "tagline": "Test copy of a German EU wallet", "system": "eu",
           "color": "#b8860b", "personas": {
               "lea": person("Lea", "Beispiel", "1990-07-01", "DE", "DE"),
               "jonas": person("Jonas", "Beispiel", "2012-09-30", "DE", "DE")}},
    "ch": {"name": "swiyu", "tagline": "Test copy of the Swiss e-ID app", "system": "ch",
           "color": "#c8102e", "personas": {
               "heidi": person("Heidi", "Muster", "1985-02-11", "CH", "fedpol")}},
}
CLAIM_LABELS = {"given_name": "First name", "family_name": "Last name", "issuing_country": "Issuing country",
                "issuing_authority": "Issuing authority", "age_over_18": "Over 18"}
COUNTRIES = {"IT": "Italy", "DE": "Germany", "CH": "Switzerland"}


def is_adult(born: str) -> bool:
    b, t = date.fromisoformat(born), date.today()
    return t.year - b.year - ((t.month, t.day) < (b.month, b.day)) >= 18


def claim_value(p: dict, claim: str):
    """What the wallet would disclose for one requested claim. The birth date itself never leaves."""
    return is_adult(p["birthdate"]) if claim == "age_over_18" else p.get(claim)


def shown(claim: str, value) -> str:
    if claim == "age_over_18":
        return "Yes" if value else "No"
    if claim == "issuing_country":
        return f"{COUNTRIES.get(value, value)} ({value})"
    return str(value)


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))
templates.env.globals.update(apps=APPS, labels=CLAIM_LABELS, shown=shown, claim_value=claim_value,
                             is_adult=is_adult, countries=COUNTRIES)
http = httpx.AsyncClient(timeout=10)


def get_app(app_id: str) -> dict:
    if app_id not in APPS:
        raise HTTPException(status_code=404)
    return APPS[app_id]


def check_request_uri(request_uri: str) -> str:
    u = urlparse(request_uri)
    if f"{u.scheme}://{u.netloc}" != VERIFIER_ORIGIN or not u.path.startswith("/test-wallet-api/requests/"):
        raise HTTPException(status_code=400, detail=f"Only requests from {VERIFIER_ORIGIN} can be opened here.")
    return request_uri


async def fetch_request(request_uri: str) -> dict:
    resp = await http.get(check_request_uri(request_uri))
    if resp.status_code != 200:
        raise HTTPException(status_code=410, detail="This request has expired or was already answered. "
                                                    "Go back to the verifier and start again.")
    return resp.json()


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request, "home.html", {})


@app.get("/{system}/present", response_class=HTMLResponse)
async def open_with(request: Request, system: str, request_uri: str):
    """What tapping a wallet link does on a phone: pick which installed app opens it."""
    matching = [a for a, v in APPS.items() if v["system"] == system]
    if system not in ("eu", "ch") or not matching:
        raise HTTPException(status_code=404)
    if len(matching) == 1:
        return RedirectResponse(f"/{matching[0]}/consent?request_uri={quote(request_uri, safe='')}", status_code=303)
    return templates.TemplateResponse(request, "open_with.html", {"matching": matching, "request_uri": request_uri})


@app.get("/{app_id}", response_class=HTMLResponse)
async def app_home(request: Request, app_id: str):
    return templates.TemplateResponse(request, "app_home.html", {"app_id": app_id, "a": get_app(app_id)})


@app.get("/{app_id}/consent", response_class=HTMLResponse)
async def consent(request: Request, app_id: str, request_uri: str):
    a = get_app(app_id)
    req = await fetch_request(request_uri)
    if req.get("system") != a["system"]:
        raise HTTPException(status_code=400, detail=f"{a['name']} (TEST) can't open this kind of request.")
    return templates.TemplateResponse(request, "consent.html",
                                      {"app_id": app_id, "a": a, "req": req, "request_uri": request_uri})


@app.post("/{app_id}/consent", response_class=HTMLResponse)
async def answer(request: Request, app_id: str, request_uri: str = Form(...), decision: str = Form(...),
                 persona: str = Form("")):
    a = get_app(app_id)
    req = await fetch_request(request_uri)
    claims = {}
    if decision == "share":
        p = a["personas"].get(persona)
        if p is None:
            raise HTTPException(status_code=400, detail="Pick one of the identities in this app.")
        claims = {c: claim_value(p, c) for c in req["requested_claims"]}
    resp = await http.post(check_request_uri(req["response_uri"]),
                           json={"nonce": req["nonce"], "decision": decision, "claims": claims})
    ok = resp.status_code == 200
    detail = "" if ok else (resp.json().get("error") if resp.headers.get("content-type", "").startswith("application/json") else resp.text[:200])
    return templates.TemplateResponse(request, "done.html", {"app_id": app_id, "a": a, "req": req, "ok": ok,
                                                             "decision": decision, "detail": detail})


@app.exception_handler(HTTPException)
async def error_page(request: Request, exc: HTTPException):
    return templates.TemplateResponse(request, "error.html", {"detail": exc.detail}, status_code=exc.status_code)
