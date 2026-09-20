"""Servidor de licenciamento do Kairos.

Roda separado do app desktop, em algum lugar que você controla (Render,
Railway, Fly.io, ou uma VPS simples) — nunca dentro do .exe do cliente.

Duas partes:
1. API (/api/*) — chamada pelo app cliente (license_client.py) pra
   ativar/validar/desativar. Sem autenticação de usuário (a "senha" é a
   própria chave de licença), mas roda só sobre HTTPS.
2. Painel admin (/admin/*) — pra VOCÊ gerenciar licenças (criar, revogar,
   liberar vagas). Protegido por usuário/senha (HTTP Basic).

Rodar localmente pra testar:
    uvicorn main:app --reload --port 8000
"""
from __future__ import annotations

import os
import re
import secrets as pysecrets

import bcrypt
from fastapi import FastAPI, Request, Depends, HTTPException, Form, Header
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

import db
import licensing

app = FastAPI(title="Kairos License Server")
templates = Jinja2Templates(directory="templates")
security = HTTPBasic()


@app.on_event("startup")
def _startup():
    db.init_schema()


# ---------------------------------------------------------------------------
# ROTA TEMPORÁRIA DE DIAGNÓSTICO — REMOVER DEPOIS DE RESOLVER O LOGIN.
# Não expõe a senha nem o hash completo — só estrutura (tamanho, formato,
# primeiros/últimos caracteres) suficiente pra detectar espaço/quebra de
# linha grudada nas variáveis de ambiente sem vazar segredo nenhum.
# ---------------------------------------------------------------------------
_BCRYPT_RE = re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")


@app.get("/debug/env-check")
def debug_env_check():
    admin_user = os.environ.get("ADMIN_USER", "")
    admin_hash = os.environ.get("ADMIN_PASSWORD_HASH", "")
    return JSONResponse({
        "ADMIN_USER": {
            "tamanho": len(admin_user),
            "repr": repr(admin_user),  # mostra espaço/tab/quebra de linha se houver
        },
        "ADMIN_PASSWORD_HASH": {
            "tamanho": len(admin_hash),
            "esperado": 60,
            "comeca_com": admin_hash[:7] if admin_hash else "(vazio)",
            "termina_com": repr(admin_hash[-5:]) if admin_hash else "(vazio)",
            "formato_bcrypt_valido": bool(_BCRYPT_RE.match(admin_hash)),
        },
    })


class _DebugPasswordCheck(BaseModel):
    password: str


@app.post("/debug/check-password")
def debug_check_password(body: _DebugPasswordCheck):
    """TEMPORÁRIO — testa se a senha enviada bate com o ADMIN_PASSWORD_HASH
    salvo, sem expor o hash. Usado só pra descartar erro de digitação.
    REMOVER esta rota assim que o login funcionar (é um oráculo de senha,
    não deve ficar em produção)."""
    admin_hash = os.environ.get("ADMIN_PASSWORD_HASH", "")
    if not admin_hash:
        return JSONResponse({"match": False, "motivo": "ADMIN_PASSWORD_HASH vazio no servidor"})
    match = bcrypt.checkpw(body.password.encode("utf-8"), admin_hash.encode("utf-8"))
    return JSONResponse({"match": match})


# ---------------------------------------------------------------------------
# Autenticação do painel admin — usuário/senha vêm do .env, nunca hardcoded.
# Gere o hash com: python -c "import bcrypt; print(bcrypt.hashpw(b'suasenha', bcrypt.gensalt()).decode())"
# ---------------------------------------------------------------------------
def _check_app_secret(x_app_secret: str = Header(default="")) -> None:
    """Autentica chamadas do PRÓPRIO app desktop (não do painel admin) — ex:
    o cadastro automático de licença. É um segredo simples (não é senha de
    usuário nenhum), só pra essa rota não ficar aberta pra qualquer um criar
    licenças em massa. O mesmo valor precisa estar no config.toml do app
    (chave APP_SHARED_SECRET), embutido no instalador."""
    expected = os.environ.get("APP_SHARED_SECRET", "")
    if not expected or not pysecrets.compare_digest(x_app_secret, expected):
        raise HTTPException(status_code=401, detail="Segredo do app inválido ou ausente.")


def _check_admin(credentials: HTTPBasicCredentials = Depends(security)) -> None:
    admin_user = os.environ.get("ADMIN_USER", "")
    admin_hash = os.environ.get("ADMIN_PASSWORD_HASH", "")
    user_ok = pysecrets.compare_digest(credentials.username, admin_user)
    pass_ok = bool(admin_hash) and bcrypt.checkpw(
        credentials.password.encode("utf-8"), admin_hash.encode("utf-8")
    )
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=401, detail="Credenciais inválidas", headers={"WWW-Authenticate": "Basic"})


# ---------------------------------------------------------------------------
# API — usada pelo app cliente (Kairos.exe)
# ---------------------------------------------------------------------------
class ActivateRequest(BaseModel):
    license_key: str
    hardware_id: str


class ValidateRequest(BaseModel):
    license_key: str
    hardware_id: str


@app.post("/api/activate")
def api_activate(body: ActivateRequest):
    ok, message, lic = licensing.activate(body.license_key.strip(), body.hardware_id.strip())
    return {
        "valid": ok,
        "message": message,
        "expires_at": lic["expires_at"].isoformat() if (lic and lic["expires_at"]) else None,
    }


@app.post("/api/validate")
def api_validate(body: ValidateRequest):
    return licensing.validate(body.license_key.strip(), body.hardware_id.strip())


class RegisterLicenseRequest(BaseModel):
    username: str
    email: str
    hardware_id: str


@app.post("/api/register-license")
def api_register_license(body: RegisterLicenseRequest, _=Depends(_check_app_secret)):
    """Chamada pelo app desktop assim que uma conta é criada (ver
    license_client.register_license) — não é chamada pelo usuário final
    diretamente, nem exige o serial. Só registra a licença no painel,
    pronta pra você ativar/entregar manualmente."""
    lic = licensing.create_pending_license_from_signup(
        customer_name=body.username.strip(),
        customer_email=body.email.strip(),
        hardware_id=body.hardware_id.strip(),
    )
    return {"ok": True, "license_key": lic["license_key"]}


@app.post("/api/deactivate")
def api_deactivate(body: ActivateRequest):
    """O próprio cliente pode chamar isso antes de desinstalar/trocar de
    máquina, pra liberar a vaga sem precisar falar com o suporte."""
    with db.get_cursor() as cur:
        cur.execute(
            """
            UPDATE activations SET deactivated_at = now()
            WHERE hardware_id = %s AND license_id = (
                SELECT id FROM licenses WHERE license_key = %s
            )
            """,
            (body.hardware_id.strip(), body.license_key.strip()),
        )
    return {"ok": True}


# ---------------------------------------------------------------------------
# Painel admin — telas HTML simples, protegidas por Basic Auth
# ---------------------------------------------------------------------------
@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request, _=Depends(_check_admin)):
    licenses = licensing.list_licenses()
    return templates.TemplateResponse(request, "admin.html", {"licenses": licenses})


@app.post("/admin/licenses")
def admin_create_license(
    customer_name: str = Form(""),
    customer_email: str = Form(""),
    max_activations: int = Form(1),
    expires_at: str = Form(""),  # yyyy-mm-dd ou vazio
    notes: str = Form(""),
    hardware_id: str = Form(""),  # opcional - amarra a chave a esta maquina ja na criacao
    _=Depends(_check_admin),
):
    licensing.create_license(
        customer_name=customer_name,
        customer_email=customer_email,
        max_activations=max_activations,
        expires_at=(expires_at or None),
        notes=notes,
        hardware_id=(hardware_id.strip() or None),
    )
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/licenses/{license_id}/revoke")
def admin_revoke(license_id: int, _=Depends(_check_admin)):
    licensing.revoke_license(license_id)
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/licenses/{license_id}/reactivate")
def admin_reactivate(license_id: int, _=Depends(_check_admin)):
    licensing.reactivate_license(license_id)
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/licenses/{license_id}/delete")
def admin_delete(license_id: int, _=Depends(_check_admin)):
    """Diferente de /revoke: apaga a licenca e o historico de ativacoes
    dela de vez (via ON DELETE CASCADE). Revoke continua sendo a opcao
    reversivel (da pra reativar depois); delete nao tem volta."""
    licensing.delete_license(license_id)
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/activations/{activation_id}/deactivate")
def admin_deactivate_seat(activation_id: int, _=Depends(_check_admin)):
    licensing.deactivate_seat(activation_id)
    return RedirectResponse(url="/admin", status_code=303)
