"""Regras de negócio do licenciamento — quem decide "pode ou não pode" é
sempre o Neon (fonte de verdade), nunca o cliente. Toda a proteção real
está aqui: mesmo que o .exe seja adulterado localmente, ele não consegue
mudar o que está gravado nesta base."""
from __future__ import annotations

import secrets
from datetime import datetime, timezone

from db import get_cursor


def generate_license_key() -> str:
    """Formato: KAIROS-XXXX-XXXX-XXXX-XXXX. A unicidade real é garantida
    pela constraint UNIQUE no banco — aqui só tenta até não colidir."""
    groups = "-".join(secrets.token_hex(2).upper() for _ in range(4))
    return f"KAIROS-{groups}"


def create_license(
    customer_name: str = "",
    customer_email: str = "",
    max_activations: int = 1,
    expires_at: str | None = None,  # ISO date string ou None (vitalícia)
    notes: str = "",
    hardware_id: str | None = None,  # se preenchido, amarra a chave a esta maquina ja na criacao
) -> dict:
    for _ in range(5):  # tentativas em caso de colisão (extremamente raro)
        key = generate_license_key()
        try:
            with get_cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO licenses (license_key, customer_name, customer_email,
                                           max_activations, expires_at, notes, bound_hardware_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING *
                    """,
                    (key, customer_name, customer_email, max_activations, expires_at, notes,
                     (hardware_id or None)),
                )
                return cur.fetchone()
        except Exception as exc:
            if "unique" in str(exc).lower():
                continue
            raise
    raise RuntimeError("Não consegui gerar uma chave única após várias tentativas.")


def _get_license_by_key(cur, license_key: str) -> dict | None:
    cur.execute("SELECT * FROM licenses WHERE license_key = %s", (license_key,))
    return cur.fetchone()


def create_pending_license_from_signup(
    customer_name: str, customer_email: str, hardware_id: str
) -> dict:
    """Chamada pelo app desktop (license_client.register_license) assim que
    alguém cria uma conta por lá — não pelo painel admin. Só REGISTRA a
    licença com os dados do cadastro (nome/e-mail já preenchidos, chave já
    gerada), sem ativar nem amarrar a nenhuma máquina: quem decide liberar
    de fato (revisar, mandar a chave pro cliente, ativar) continua sendo
    você, manualmente, pelo /admin — isso só elimina o trabalho de digitar
    nome/e-mail toda vez que alguém se cadastra.

    Idempotente por e-mail: se essa pessoa já se cadastrou antes (ex: reabriu
    o cadastro, ou reinstalou o app antes de completar a compra), devolve a
    licença já existente em vez de criar uma segunda pra ela."""
    with get_cursor() as cur:
        cur.execute(
            "SELECT * FROM licenses WHERE customer_email = %s ORDER BY created_at ASC LIMIT 1",
            (customer_email,),
        )
        existing = cur.fetchone()
        if existing:
            return dict(existing)

    return create_license(
        customer_name=customer_name,
        customer_email=customer_email,
        max_activations=1,
        notes=f"Criada automaticamente pelo cadastro no app (hardware_id: {hardware_id}).",
    )


def activate(license_key: str, hardware_id: str) -> tuple[bool, str, dict | None]:
    """Ativa `hardware_id` numa licença. Idempotente: reativar a mesma
    máquina não gasta cota nova. Retorna (sucesso, mensagem, dados)."""
    with get_cursor() as cur:
        lic = _get_license_by_key(cur, license_key)
        if lic is None:
            return False, "Chave de licença não encontrada.", None
        if lic["status"] == "revoked":
            return False, "Esta licença foi revogada.", None
        if lic["expires_at"] and lic["expires_at"] < datetime.now(timezone.utc):
            return False, "Esta licença está expirada.", None
        if lic["bound_hardware_id"] and lic["bound_hardware_id"] != hardware_id:
            # Chave pre-amarrada (no painel, na criacao) a OUTRA maquina -
            # nem chega a olhar cota/ativacoes existentes, rejeita direto.
            return False, (
                "Esta licença está vinculada a outro computador e não pode "
                "ser ativada aqui. Fale com o suporte se acha que isso é um erro."
            ), None

        cur.execute(
            "SELECT * FROM activations WHERE license_id = %s AND hardware_id = %s",
            (lic["id"], hardware_id),
        )
        existing = cur.fetchone()
        if existing:
            if existing["deactivated_at"] is not None:
                # vaga que foi liberada antes (ex: reinstalação) -> reocupa
                cur.execute(
                    "UPDATE activations SET deactivated_at = NULL, last_seen_at = now() "
                    "WHERE id = %s",
                    (existing["id"],),
                )
            else:
                cur.execute(
                    "UPDATE activations SET last_seen_at = now() WHERE id = %s",
                    (existing["id"],),
                )
            return True, "Licença ativada com sucesso!", dict(lic)

        cur.execute(
            "SELECT COUNT(*) AS n FROM activations WHERE license_id = %s AND deactivated_at IS NULL",
            (lic["id"],),
        )
        active_count = cur.fetchone()["n"]
        if active_count >= lic["max_activations"]:
            return False, (
                f"Esta licença já está em uso no limite de {lic['max_activations']} "
                "máquina(s). Libere uma ativação antiga (fale com o suporte) antes de ativar aqui."
            ), None

        cur.execute(
            "INSERT INTO activations (license_id, hardware_id) VALUES (%s, %s)",
            (lic["id"], hardware_id),
        )
        return True, "Licença ativada com sucesso!", dict(lic)


def validate(license_key: str, hardware_id: str) -> dict:
    """Checagem periódica (chamada pelo app a cada abertura ou a cada N
    dias). Sempre atualiza last_seen_at quando válida, pra você enxergar
    no painel quando cada máquina foi vista pela última vez."""
    with get_cursor() as cur:
        lic = _get_license_by_key(cur, license_key)
        if lic is None:
            return {"valid": False, "reason": "not_found", "message": "Licença não encontrada."}
        if lic["status"] == "revoked":
            return {"valid": False, "reason": "revoked", "message": "Licença revogada."}
        if lic["expires_at"] and lic["expires_at"] < datetime.now(timezone.utc):
            return {"valid": False, "reason": "expired", "message": "Licença expirada."}

        cur.execute(
            "SELECT * FROM activations WHERE license_id = %s AND hardware_id = %s",
            (lic["id"], hardware_id),
        )
        act = cur.fetchone()
        if act is None or act["deactivated_at"] is not None:
            return {
                "valid": False, "reason": "not_activated",
                "message": "Esta máquina não está ativada para esta licença.",
            }

        cur.execute("UPDATE activations SET last_seen_at = now() WHERE id = %s", (act["id"],))
        return {
            "valid": True, "reason": "ok", "message": "Licença ativa.",
            "expires_at": lic["expires_at"].isoformat() if lic["expires_at"] else None,
        }


def deactivate_seat(activation_id: int) -> None:
    """Libera uma vaga (usado pelo painel admin, ou pelo próprio cliente
    antes de desinstalar/trocar de máquina)."""
    with get_cursor() as cur:
        cur.execute(
            "UPDATE activations SET deactivated_at = now() WHERE id = %s",
            (activation_id,),
        )


def revoke_license(license_id: int) -> None:
    with get_cursor() as cur:
        cur.execute("UPDATE licenses SET status = 'revoked' WHERE id = %s", (license_id,))


def reactivate_license(license_id: int) -> None:
    with get_cursor() as cur:
        cur.execute("UPDATE licenses SET status = 'active' WHERE id = %s", (license_id,))


def delete_license(license_id: int) -> None:
    """Apaga a licença DE VEZ (diferente de revoke_license, que so muda o
    status e mantem o historico). O "ON DELETE CASCADE" da tabela
    activations (ver schema_licenses.sql) apaga as ativacoes junto
    automaticamente - nao precisa apagar elas separado aqui."""
    with get_cursor() as cur:
        cur.execute("DELETE FROM licenses WHERE id = %s", (license_id,))


def list_licenses() -> list[dict]:
    with get_cursor() as cur:
        cur.execute("SELECT * FROM licenses ORDER BY created_at DESC")
        licenses = cur.fetchall()
        for lic in licenses:
            cur.execute(
                "SELECT * FROM activations WHERE license_id = %s ORDER BY activated_at DESC",
                (lic["id"],),
            )
            lic["activations"] = cur.fetchall()
        return licenses
