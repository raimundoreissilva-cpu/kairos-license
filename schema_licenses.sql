-- Tabelas de licenciamento do Kairos, no MESMO banco Neon que o app já usa
-- (a DATABASE_URL do config.toml). Separadas do schema.sql do app desktop
-- (que é SQLite local, outro banco) — este arquivo roda só no servidor.

CREATE TABLE IF NOT EXISTS licenses (
    id SERIAL PRIMARY KEY,
    license_key TEXT UNIQUE NOT NULL,           -- ex: KAIROS-A1B2-C3D4-E5F6-1122
    customer_name TEXT,
    customer_email TEXT,
    max_activations INTEGER NOT NULL DEFAULT 1, -- quantas máquinas essa chave pode ativar ao mesmo tempo
    expires_at TIMESTAMPTZ,                      -- NULL = vitalícia
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    notes TEXT
);

-- Se preenchido, a chave só pode ser ativada NESTA maquina especifica (o
-- hardware_id enviado em /api/activate precisa bater com este valor) -
-- amarrado ja na GERACAO da chave, no painel admin, em vez de aceitar
-- qualquer primeira maquina que ativar (comportamento antigo, que
-- continua valendo quando este campo fica NULL). "ADD COLUMN IF NOT
-- EXISTS" e nativo do Postgres (diferente do schema.sql SQLite do app
-- desktop) - roda de novo sem erro em bancos que ja tem a coluna.
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS bound_hardware_id TEXT;

-- Cada linha = uma máquina que ativou aquela chave. UNIQUE(license_id,
-- hardware_id) garante que a mesma máquina não ocupa 2 "vagas" ativando
-- de novo — reativar é idempotente, não gasta cota extra.
CREATE TABLE IF NOT EXISTS activations (
    id SERIAL PRIMARY KEY,
    license_id INTEGER NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    hardware_id TEXT NOT NULL,
    activated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(), -- atualizado a cada /validate
    deactivated_at TIMESTAMPTZ,                       -- NULL = vaga em uso
    UNIQUE (license_id, hardware_id)
);

CREATE INDEX IF NOT EXISTS idx_activations_license ON activations(license_id);
CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key);
