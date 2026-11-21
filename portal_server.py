#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Portal Cativo NewsInside_Portal — Omada SDN + LivePix
=======================================================

Fluxo completo de um portal cativo (captive portal) para redes Omada/TP-Link:

  1. Cliente conecta ao SSID do portal (ex.: NewsInside_Portal)
  2. EAP intercepta e redireciona para este portal com parâmetros Omada
     (clientMac, clientIp, apMac, ssidName, radioId, vid, t)
  3. Usuário faz cadastro (LGPD-compliant) ou login
  4. Geração de cobrança PIX via LivePix (R$ 5,00 padrão; R$ 25,00 Apple)
  5. Após confirmação do pagamento, autorização via Omada extPortal auth
     (authType 4 — 1 hora, rate limit configurável)
  6. Sessão expira automaticamente; expiração varre e desautoriza no Omada

LGPD (Lei 13.709/2018):
  • Consentimento explícito no cadastro e login
  • CPF armazenado APENAS como hash SHA-256 (nunca em claro)
  • Nome de registro NÃO é lido/exposto quando usa nome social
  • Direitos do titular: exportação (/me/export) e exclusão total (/me/delete)
  • Retenção configurável (padrão: 90 dias); logs por usuário em texto + JSON
  • Validação opcional via Cadastro Base do Cidadão (CBC — gov.br/Serpro)

Execução:
  $ cp .env.example .env   # edite com seus valores
  $ source .env            # ou defina as vars no ambiente
  $ python3 portal_server.py

Acesse: http://localhost:8089 (ou a porta configurada)
"""

import os
import json
import time
import hmac
import uuid
import secrets
import hashlib
import sqlite3
import threading
import http.cookiejar
import urllib.request
import urllib.error
import urllib.parse
import ssl
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# ---------------------------------------------------------------------------
# Diretórios e caminhos (relativos a este arquivo para portabilidade)
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
USERS_DIR = LOGS_DIR / "usuarios"
DB_PATH = DATA_DIR / "portal.db"
CONFIG_PATH = DATA_DIR / "config.json"

# ---------------------------------------------------------------------------
# Configuração padrão (valores seguros / exemplos — sobreponha via config.json
# e/ou variáveis de ambiente)
# ---------------------------------------------------------------------------
DEFAULT_CONFIG = {
    # Endpoint do controller Omada (ex.: https://localhost:8043)
    "controller_base": "https://localhost:8043",
    # ID do Omada Controller (aparece na URL da web UI após login)
    "omadac_id": "SUA_OMADAC_ID_AQUI",
    # ID do site no Omada
    "site_id": "SEU_SITE_ID_AQUI",
    # URL pública do portal vista pelos clientes (ex.: http://192.168.0.3:8089)
    "portal_public_base": "http://127.0.0.1:8089",
    # Duração da sessão autorizada em minutos
    "session_duration_min": 60,
    # Preço do PIX em centavos (R$ 5,00 = 500 centavos)
    "price_brl_cents": 500,
    # Preço para dispositivos Apple (R$ 25,00 = 2500 centavos)
    "price_apple_brl_cents": 2500,
    # Limite de taxa autorizado no Omada (kbps)
    "rate_limit_kbps": 250000,
    "apple_rate_limit_kbps": 100000,
    # Retenção de logs/dados em dias (LGPD)
    "retention_days": 90,
    # Porta de escuta do portal
    "portal_listen_port": 8089,
    # ---- Cadastro Base do Cidadão (CBC — gov.br/Serpro) ----
    # off = validação local apenas | homolog = sandbox Serpro | prod = produção
    "cbc_env": "off",
    "cbc_base_homolog": "https://h-apigateway.conectagov.np.estaleiro.serpro.gov.br",
    "cbc_base_prod": "https://apigateway.conectagov.estaleiro.serpro.gov.br",
    "cbc_timeout_s": 10,
    # Se True, bloqueia cadastro quando a CBC estiver indisponível
    "cbc_required": False,
}

# ---------------------------------------------------------------------------
# Secrets: NUNCA em disco. São lidos exclusivamente de variáveis de ambiente.
# Cada chave mapeia: chave_de_config -> nome_da_variavel_de_ambiente
# ---------------------------------------------------------------------------
ENV_SECRET = {
    "livepix_client_id": "LIVEPIX_CLIENT_ID",
    "livepix_client_secret": "LIVEPIX_CLIENT_SECRET",
    "hotspot_operator": "HOTSPOT_OPERATOR",
    "hotspot_password": "HOTSPOT_PASSWORD",
    "cbc_client_id": "CBC_CLIENT_ID",
    "cbc_client_secret": "CBC_CLIENT_SECRET",
    "cbc_cpf_usuario": "CBC_X_CPF_USUARIO",  # CPF do responsável (header x-cpf-usuario)
}

# Usuários de teste (podem simular pagamento sem PIX real).
# Defina via env PORTAL_TEST_USERS="Amielle,outro"
TEST_USERS = {u.strip().lower() for u in os.environ.get("PORTAL_TEST_USERS", "").split(",") if u.strip()}


def load_config():
    """
    Carrega a configuração mesclando DEFAULT_CONFIG < config.json < env vars.
    Secrets só entram se a variável de ambiente correspondente estiver definida.
    """
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        try:
            cfg.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            pass  # ignora config.json ausente ou inválido
    for key, env_name in ENV_SECRET.items():
        if os.environ.get(env_name):
            cfg[key] = os.environ[env_name]
        cfg.setdefault(key, "")
    return cfg


CFG = load_config()


def is_test_user(username: str) -> bool:
    """Verifica se o usuário está na lista de teste (simulação de pagamento)."""
    return bool(username) and username.lower() in TEST_USERS


# Contexto SSL que aceita certificados auto-assinados (controller local)
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


# ---------------------------------------------------------------------------
# Banco de dados SQLite
# ---------------------------------------------------------------------------
def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """Cria tabelas e aplica migrações LGPD (idempotente)."""
    for d in (DATA_DIR, LOGS_DIR, USERS_DIR):
        d.mkdir(parents=True, exist_ok=True)
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            pw_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            consent_at TEXT NOT NULL,
            consent_ip TEXT
        );
        CREATE TABLE IF NOT EXISTS sessions(
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            client_mac TEXT,
            client_ip TEXT,
            ap_mac TEXT,
            ssid_name TEXT,
            radio_id TEXT,
            device_os TEXT,
            is_apple INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            authorized INTEGER DEFAULT 0,
            authorized_at TEXT,
            payment_ref TEXT
        );
        CREATE TABLE IF NOT EXISTS payments(
            reference TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            client_mac TEXT,
            amount_cents INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            checkout_url TEXT,
            created_at TEXT,
            paid_at TEXT,
            proof TEXT
        );
        """)
        # Migração LGPD: campos de identidade adicionados no cadastro
        mig = {
            "full_name": "TEXT",
            "name_is_social": "INTEGER DEFAULT 0",
            "cpf_hash": "TEXT",
            "cpf_masked": "TEXT",
            "email": "TEXT",
            "gov_status": "TEXT",
            "gov_validated_at": "TEXT",
        }
        for col, t in mig.items():
            try:
                c.execute(f"ALTER TABLE users ADD COLUMN {col} {t}")
            except sqlite3.OperationalError:
                pass  # coluna já existe


init_db()


# ---------------------------------------------------------------------------
# Senhas (scrypt)
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """Gera hash scrypt da senha. Retorna string 'scrypt$<hash>$<salt>'."""
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${h.hex()}${salt.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Verifica senha contra hash scrypt armazenado."""
    try:
        algo, phex, shex = stored.split("$")
        if algo != "scrypt":
            return False
        h = hashlib.scrypt(password.encode(), salt=bytes.fromhex(shex), n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(h.hex(), phex)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Identidade / LGPD (cadastro)
# ---------------------------------------------------------------------------
import unicodedata
import re
import struct
import random
import base64
import socket


def _unaccent(s: str) -> str:
    """Remove acentos para comparação de nomes."""
    return "".join(ch for ch in unicodedata.normalize("NFKD", s) if not unicodedata.combining(ch))


def normalize_name(s: str) -> str:
    """Minúsculas, sem acentos, espaços colapsados — para comparar com base CPF."""
    return " ".join(_unaccent(s or "").casefold().split())


def valida_cpf(cpf: str) -> bool:
    """Valida dígitos verificadores do CPF (algoritmo padrão)."""
    d = "".join(filter(str.isdigit, cpf or ""))
    if len(d) != 11 or d == d[0] * 11:
        return False
    for n in (9, 10):
        s = sum(int(d[j]) * (n + 1 - j) for j in range(n))
        if (s * 10) % 11 % 10 != int(d[n]):
            return False
    return True


def cpf_digits(cpf: str) -> str:
    """Retorna apenas os dígitos numéricos do CPF."""
    return "".join(filter(str.isdigit, cpf or ""))


def cpf_mask(cpf: str) -> str:
    """Máscara do CPF para exibição (apenas dígitos conhecidos, resto ofuscado)."""
    d = cpf_digits(cpf)
    return f"***.{d[3:6]}.{d[6:9]}-**" if len(d) == 11 else ""


def cpf_hash(cpf: str) -> str:
    """
    Armazena APENAS o SHA-256 do CPF (nunca o CPF em claro) — minimização LGPD.
    O salt 'portal-cpf:' evita tabelas rainbow.
    """
    return hashlib.sha256(("portal-cpf:" + cpf_digits(cpf)).encode()).hexdigest()


def valida_nome_completo(nome: str) -> bool:
    """Nome de registro: requer nome + sobrenome (mínimo 2 palavras)."""
    n = (nome or "").strip()
    return (len(n) >= 5
            and len(n.split()) >= 2
            and re.fullmatch(r"[A-Za-zÀ-ÿ'’\- ]+", n) is not None)


def valida_nome_social(nome: str) -> bool:
    """Nome social pode ser um único nome (ex.: 'Amielle')."""
    n = (nome or "").strip()
    return (len(n) >= 2
            and re.fullmatch(r"[A-Za-zÀ-ÿ'’\- ]+", n) is not None)


_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "tempmail.com", "temp-mail.org",
    "guerrillamail.com", "yopmail.com", "sharklasers.com", "getnada.com",
    "dispostable.com", "maildrop.cc", "fakeinbox.com", "mytemp.email",
    "throwawaymail.com", "mailnesia.com", "trashmail.com",
}


def _mx_existe(dominio: str, timeout_s: float = 4.0) -> bool:
    """Consulta MX via DNS bruto (stdlib). Falha silenciosa aceitável."""
    try:
        ns = None
        try:
            with open("/etc/resolv.conf") as f:
                for l in f:
                    if l.startswith("nameserver"):
                        ns = l.split()[1]; break
        except OSError:
            pass
        if not ns:
            return False
        q = b"".join(bytes([len(p)]) + p.encode() for p in dominio.split(".")) + b"\x00"
        tid = random.randint(0, 65535)
        pkt = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", 15, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout_s)
        s.sendto(pkt, (ns, 53))
        resp, _ = s.recvfrom(2048); s.close()
        ancount = struct.unpack(">H", resp[6:8])[0]
        return ancount > 0
    except Exception:
        return False


def valida_email(addr: str) -> bool:
    """Valida formato de e-mail, rejeita domínios descartáveis e verifica MX."""
    a = (addr or "").strip().lower()
    if not _EMAIL_RE.fullmatch(a) or len(a) > 254 or ".." in a:
        return False
    dom = a.rsplit("@", 1)[1]
    if dom in DISPOSABLE_DOMAINS:
        return False
    return _mx_existe(dom)


# ---- Cliente CBC (API CPF Light v2 — Cadastro Base do Cidadão) ----
_CBC_LOCK = threading.Lock()
_CBC_TOKEN = {"token": None, "exp": 0.0}


def cbc_enabled() -> bool:
    """Retorna True se a validação CBC está ativa (homolog ou prod com credenciais)."""
    return (CFG.get("cbc_env") in ("homolog", "prod")
            and CFG.get("cbc_client_id") and CFG.get("cbc_client_secret"))


def _cbc_base() -> str:
    return CFG["cbc_base_prod"] if CFG["cbc_env"] == "prod" else CFG["cbc_base_homolog"]


def cbc_get_token():
    """OAuth2 client_credentials (Basic). Token cacheado até expirar."""
    with _CBC_LOCK:
        now = time.time()
        if _CBC_TOKEN["token"] and now < _CBC_TOKEN["exp"] - 60:
            return _CBC_TOKEN["token"]
        b64 = base64.b64encode(f"{CFG['cbc_client_id']}:{CFG['cbc_client_secret']}".encode()).decode()
        req = urllib.request.Request(
            f"{_cbc_base()}/oauth2/jwt-token",
            data=b"grant_type=client_credentials",
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Authorization": f"Basic {b64}"})
        with urllib.request.urlopen(req, timeout=CFG["cbc_timeout_s"], context=SSL_CTX) as r:
            d = json.loads(r.read().decode())
        tok = d.get("access_token")
        exp = now + 6000
        try:
            payload = tok.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            exp = json.loads(base64.urlsafe_b64decode(payload)).get("exp", now + 6000)
        except Exception:
            pass
        _CBC_TOKEN.update(token=tok, exp=float(exp))
        return tok


def cbc_consulta_cpf(cpf: str):
    """
    Consulta CPF Light v2. Retorna dict {nome, nome_social, situacao, desc_situacao}
    ou None se indisponível. NUNCA loga o corpo da resposta.
    """
    try:
        tok = cbc_get_token()
        req = urllib.request.Request(
            f"{_cbc_base()}/api-cpf-light/v2/consulta/cpf",
            data=json.dumps({"listaCpf": [cpf_digits(cpf)]}).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {tok}",
                     "x-cpf-usuario": cpf_digits(CFG.get("cbc_cpf_usuario") or "")})
        with urllib.request.urlopen(req, timeout=CFG["cbc_timeout_s"], context=SSL_CTX) as r:
            data = json.loads(r.read().decode())
        item = (data or [None])[0] or {}
        return {
            "nome": item.get("Nome") or "",
            "nome_social": item.get("NomeSocial") or "",
            "situacao": str(item.get("SituacaoCadastral", "")),
            "desc_situacao": item.get("DescSituacaoCadastral") or "",
        }
    except Exception as e:
        log_system(f"CBC indisponível ({type(e).__name__}) — sem detalhe de dados")
        return None


def validate_identity(nome: str, is_social: bool, cpf: str, email: str):
    """
    Validação de identidade no ato do registro (LGPD).
    Regra de nome social: se usa nome social, o CPF é validado EXCLUSIVAMENTE
    pelo NomeSocial da base oficial — o nome de registro NUNCA é lido.
    Retorna (ok: bool, errcode: str, gov_status: str).
    gov_status: 'validado' | 'pendente' | 'off'
    """
    if is_social:
        if not valida_nome_social(nome):
            return False, "nome", "off"
    else:
        if not valida_nome_completo(nome):
            return False, "nome", "off"
    if not valida_cpf(cpf):
        return False, "cpf", "off"
    if not valida_email(email):
        return False, "email", "off"
    if not cbc_enabled():
        return True, "", "off"
    dados = cbc_consulta_cpf(cpf)
    if dados is None:
        if CFG.get("cbc_required"):
            return False, "gov_off", "pendente"
        return True, "", "pendente"
    if "regular" not in (dados["desc_situacao"] or "").casefold():
        return False, "sit", "pendente"
    if is_social:
        # FLUXO SOCIAL: olha SOMENTE o NomeSocial; descarta Nome de registro
        social = (dados.get("nome_social") or "").strip()
        dados.pop("nome", None)  # nome de registro: NUNCA lido/exposto
        if not social:
            return False, "social_ausente", "pendente"
        if normalize_name(social) != normalize_name(nome):
            return False, "social_nao_bate", "pendente"
        return True, "", "validado"
    # fluxo não-social: compara com nome de registro
    if normalize_name(dados.get("nome") or "") != normalize_name(nome):
        return False, "nome_nao_bate", "pendente"
    return True, "", "validado"


# ---------------------------------------------------------------------------
# Logs (LGPD)
# ---------------------------------------------------------------------------
def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def safe_name(u: str) -> str:
    """Nome seguro para nomes de arquivo de log (somente alfanumérico)."""
    return "".join(ch for ch in u if ch.isalnum() or ch in "._-")[:64] or "anon"


def log_user_event(username: str, event: dict):
    """
    Log por usuário: .log (legível) + .jsonl (JSON) em logs/usuarios/.
    Não armazena nome completo nem CPF — apenas status e metadados.
    """
    ts = now_iso()
    event = {"ts": ts, **event}
    base = USERS_DIR / safe_name(username)
    with open(str(base) + ".log", "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {event.get('event','?')} | " +
                " ".join(f"{k}={v}" for k, v in event.items() if k not in ("ts", "event")) + "\n")
    with open(str(base) + ".jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def log_system(msg: str):
    with open(LOGS_DIR / "portal.log", "a", encoding="utf-8") as f:
        f.write(f"[{now_iso()}] {msg}\n")


# ---------------------------------------------------------------------------
# Detecção de dispositivo
# ---------------------------------------------------------------------------
def detect_apple(user_agent: str) -> bool:
    ua = (user_agent or "").lower()
    return any(t in ua for t in ("iphone", "ipad", "ipod", "macintosh", "cpu iphone os", "cpu os"))


def device_os(user_agent: str) -> str:
    ua = (user_agent or "").lower()
    if "iphone" in ua or "ipad" in ua or "ipod" in ua: return "iOS/iPadOS"
    if "macintosh" in ua: return "macOS"
    if "android" in ua: return "Android"
    if "windows" in ua: return "Windows"
    if "cros" in ua: return "ChromeOS"
    if "linux" in ua: return "Linux"
    return "Outro"


# ---------------------------------------------------------------------------
# LivePix (PIX)
# ---------------------------------------------------------------------------
UA_BROWSER = "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"
_lp = {"token": None, "exp": 0}
_lp_lock = threading.Lock()


def livepix_token():
    """Obtém token OAuth2 da LivePix (client_credentials)."""
    if not CFG["livepix_client_id"] or not CFG["livepix_client_secret"]:
        raise RuntimeError("LIVEPIX_CLIENT_ID/SECRET não configurados (ver .env.example)")
    with _lp_lock:
        if _lp["token"] and time.time() < _lp["exp"] - 60:
            return _lp["token"]
        data = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": CFG["livepix_client_id"],
            "client_secret": CFG["livepix_client_secret"],
            "scope": "payments:write payments:read",
        }).encode()
        req = urllib.request.Request("https://oauth.livepix.gg/oauth2/token", data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "User-Agent": UA_BROWSER})
        with urllib.request.urlopen(req, timeout=15) as r:
            d = json.loads(r.read())
        _lp["token"] = d["access_token"]
        _lp["exp"] = time.time() + int(d.get("expires_in", 3600))
        return _lp["token"]


def _lp_call(method, path, body=None):
    req = urllib.request.Request(f"https://api.livepix.gg{path}",
        data=json.dumps(body).encode() if body else None, method=method,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {livepix_token()}",
                 "User-Agent": UA_BROWSER})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def livepix_create_payment(amount_cents: int, redirect_url: str):
    """Cria cobrança PIX na LivePix. Retorna {reference, redirectUrl}."""
    d = _lp_call("POST", "/v2/payments",
                 {"amount": amount_cents, "currency": "BRL", "redirectUrl": redirect_url})
    return d["data"]


def livepix_check_payment(reference: str):
    """Verifica se o PIX foi pago. Retorna (bool, dados_ou_None)."""
    d = _lp_call("GET", f"/v2/payments?reference={urllib.parse.quote(reference)}&limit=10")
    rows = (d or {}).get("data") or []
    return (True, rows[0]) if rows else (False, None)


# ---------------------------------------------------------------------------
# Omada SDN Controller
# ---------------------------------------------------------------------------
_om = {"token": None, "exp": 0, "cookie": ""}
_om_lock = threading.Lock()


def omada_login():
    """Faz login no controller Omada via hotspot/login. Retorna (token, cookie)."""
    with _om_lock:
        if _om["token"] and time.time() < _om["exp"] - 60:
            return _om["token"], _om["cookie"]
        base = CFG["controller_base"].rstrip("/")
        body = json.dumps({"name": CFG["hotspot_operator"],
                           "password": CFG["hotspot_password"]}).encode()
        req = urllib.request.Request(
            f"{base}/{CFG['omadac_id']}/api/v2/hotspot/login", data=body, method="POST",
            headers={"Content-Type": "application/json"})
        cj = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cj),
            urllib.request.HTTPSHandler(context=SSL_CTX))
        with opener.open(req, timeout=15) as r:
            d = json.loads(r.read())
        if d.get("errorCode") != 0:
            raise RuntimeError(f"hotspot login falhou: {d}")
        _om["token"] = d["result"]["token"]
        _om["exp"] = time.time() + 3600
        _om["cookie"] = "; ".join(f"{c.name}={c.value}" for c in cj)
        return _om["token"], _om["cookie"]


def omada_deauth(client_mac: str):
    """Encerra sessão do client no controller (cmd/clients/{mac}/unauth)."""
    base = CFG["controller_base"].rstrip("/")
    token, cookie = omada_login()
    payload = json.dumps({"clientmac": client_mac}).encode()
    req = urllib.request.Request(
        f"{base}/{CFG['omadac_id']}/api/v2/sites/{CFG['site_id']}/cmd/clients/{client_mac}/unauth",
        data=payload, method="POST",
        headers={"Content-Type": "application/json", "Csrf-Token": token,
                 "Cookie": cookie, "User-Agent": UA_BROWSER})
    with urllib.request.urlopen(req, timeout=15, context=SSL_CTX) as r:
        d = json.loads(r.read())
    if d.get("errorCode") != 0:
        raise RuntimeError(f"unauth falhou: {d}")
    return d


def omada_ext_portal_auth(client_mac, client_ip, ap_mac, ssid_name, radio_id,
                          duration_min, down_kbps, up_kbps):
    """
    Autoriza cliente via Omada External Portal (authType 4).
    Duração em milissegundos (v6 do controller).
    """
    base = CFG["controller_base"].rstrip("/")
    token, cookie = omada_login()
    payload = {
        "clientMac": client_mac,
        "clientIp": client_ip,
        "apMac": ap_mac,
        "ssidName": ssid_name,
        "radioId": str(radio_id),
        "time": int(duration_min) * 60 * 1000,
        "authType": 4,
        "downloadRateLimitKbps": down_kbps,
        "uploadRateLimitKbps": up_kbps,
    }
    req = urllib.request.Request(
        f"{base}/{CFG['omadac_id']}/api/v2/hotspot/extPortal/auth",
        data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", "Csrf-Token": token, "Cookie": cookie})
    with urllib.request.urlopen(req, timeout=15, context=SSL_CTX) as r:
        d = json.loads(r.read())
    return d.get("errorCode") == 0, d


# ---------------------------------------------------------------------------
# Servidor HTTP
# ---------------------------------------------------------------------------
def render(template: str, **kw):
    """Substitui {{chave}} por valores no template HTML (simples, sem engine)."""
    for k, v in kw.items():
        template = template.replace("{{" + k + "}}", str(v))
    return template


T_LOGIN = (BASE_DIR / "templates" / "login.html").read_text(encoding="utf-8")
T_PAY = (BASE_DIR / "templates" / "pay.html").read_text(encoding="utf-8")
T_PRIV = (BASE_DIR / "templates" / "privacy.html").read_text(encoding="utf-8")


class PortalHandler(BaseHTTPRequestHandler):
    server_version = "NewsInsidePortal/1.0"

    def log_message(self, fmt, *args):
        log_system(f"{self.client_address[0]} {fmt % args}")

    def _qs(self):
        return urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)

    def _form(self):
        length = int(self.headers.get("Content-Length", 0))
        return urllib.parse.parse_qs(self.rfile.read(length).decode())

    def _send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for h, v in (headers or {}).items():
            self.send_header(h, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")

    def _redirect(self, loc):
        self._send(302, b"", headers={"Location": loc})

    def _omada_params(self, form):
        return {k: (form.get(k) or [default])[0] for k, default in (
            ("clientMac", ""), ("clientIp", self.client_address[0]),
            ("apMac", ""), ("ssidName", "NewsInside_Portal"),
            ("radioId", "1"), ("vid", None))}

    # ---- rotas ----
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = self._qs()
        try:
            if u.path in ("/", "/login"):
                return self.page_login(q)
            if u.path == "/pay":
                return self.page_pay(q)
            if u.path == "/check":
                return self.api_check(q)
            if u.path == "/status":
                return self.api_status(q)
            if u.path == "/privacy":
                return self._send(200, T_PRIV)
            if u.path == "/me/export":
                return self.api_export_me(q)
            if u.path == "/me/delete":
                return self.api_delete_me(q)
            if u.path == "/cert/omada-portal.crt":
                data = (BASE_DIR / "static" / "omada-portal.crt").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/x-x509-ca-cert")
                self.send_header("Content-Disposition", 'attachment; filename="omada-portal.crt"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            self._send(404, "Not found")
        except Exception as e:
            log_system(f"ERRO GET {u.path}: {e!r}")
            self._send(500, "Erro interno")

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        try:
            if u.path == "/register":
                return self.api_register()
            if u.path == "/login":
                return self.api_login()
            if u.path == "/pay/create":
                return self.api_pay_create()
            if u.path == "/pay/simulate":
                return self.api_pay_simulate()
            if u.path == "/check":
                return self.api_check(self._qs())
            self._send(404, "Not found")
        except Exception as e:
            log_system(f"ERRO POST {u.path}: {e!r}")
            self._send(500, "Erro interno")

    # ---- páginas ----
    def page_login(self, q):
        hidden = "".join(f'<input type="hidden" name="{k}" value="{v[0]}">' for k, v in q.items())
        msgs = {
            "user": "Usuário ou senha inválidos.",
            "consent": "Aceite a política de privacidade para continuar.",
            "exists": "Este usuário já existe. Use a aba Entrar.",
            "pw": "A senha deve ter ao menos 8 caracteres.",
            "nome": "Informe seu nome completo (nome e sobrenome, só letras).",
            "cpf": "CPF inválido — confira os números digitados.",
            "cpf_duplicado": "Este CPF já possui conta neste portal. Use a aba Entrar.",
            "email": "E-mail inválido — verifique o endereço (domínios temporários não são aceitos).",
            "gov_off": "Não foi possível validar seus dados na base do CPF agora. Tente novamente em instantes.",
            "sit": "CPF com situação cadastral irregular na Receita Federal. Regularize para se cadastrar.",
            "nome_nao_bate": "O nome informado não corresponde ao nome registrado no CPF.",
            "social_ausente": "Este CPF ainda não possui nome social registrado na Receita Federal.",
            "social_nao_bate": "O nome social informado não corresponde ao nome social registrado no CPF.",
        }
        msg = f'<p class="err">{msgs[q["err"][0]]}</p>' if q.get("err") else ""
        if cbc_enabled():
            dados_c = ("nome, CPF validado na base oficial da Receita Federal, e-mail, dados de acesso")
        else:
            dados_c = ("nome, CPF verificado por dígito verificador e unicidade (validação local), "
                       "e-mail, dados de acesso")
        self._send(200, render(T_LOGIN, hidden_fields=hidden, msg=msg, dados_consent=dados_c))

    def page_pay(self, q):
        token = (q.get("t") or [""])[0]
        row = self._session(token)
        if not row:
            return self._send(403, "Sessão inválida ou expirada. <a href='/login'>Voltar</a>")
        if row["authorized"]:
            return self._send(200, "<h2>✅ Acesso ativo — 1 hora liberada. Pode fechar esta página.</h2>")
        amount = CFG["price_apple_brl_cents"] if row["is_apple"] else CFG["price_brl_cents"]
        valor = f"R$ {amount // 100},{amount % 100:02d}"
        user = self._username(row["user_id"])
        test_block = ""
        if is_test_user(user):
            test_block = ('<a class="btn" href="#" onclick="simulatePix(event)" '
                          'style="background:#8a5cff;margin-top:10px">🧪 Simular pagamento (teste admin)</a>')
        self._send(200, render(T_PAY, token=token, valor=valor, test_block=test_block,
                               username=user or "", device=row["device_os"] or ""))

    # ---- APIs ----
    def api_register(self):
        form = self._form()
        username = (form.get("username") or [""])[0].strip()[:64]
        password = (form.get("password") or [""])[0]
        full_name = (form.get("full_name") or [""])[0].strip()[:120]
        is_social = bool(form.get("name_is_social"))
        cpf = (form.get("cpf") or [""])[0].strip()[:20]
        email = (form.get("email") or [""])[0].strip().lower()[:254]
        if not username or not password:
            return self._redirect("/login?err=user")
        if len(password) < 8:
            return self._redirect("/login?err=pw")
        if not form.get("consent"):
            return self._redirect("/login?err=consent")
        # Validação de identidade no ato do registro (LGPD)
        ok, errcode, gov_status = validate_identity(full_name, is_social, cpf, email)
        if not ok:
            om = self._omada_params(form)
            qs = urllib.parse.urlencode({**{k: v for k, v in om.items() if v}, "err": errcode})
            return self._redirect("/login?" + qs)
        cpf_h = cpf_hash(cpf)
        with db() as c:
            if c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                return self._redirect("/login?err=exists")
            if c.execute("SELECT 1 FROM users WHERE cpf_hash=?", (cpf_h,)).fetchone():
                return self._redirect("/login?err=cpf_duplicado")
            uid = uuid.uuid4().hex
            c.execute("""INSERT INTO users(id,username,pw_hash,created_at,consent_at,consent_ip,
                full_name,name_is_social,cpf_hash,cpf_masked,email,gov_status,gov_validated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (uid, username, hash_password(password), now_iso(), now_iso(), self.client_address[0],
                 full_name, int(is_social), cpf_h, cpf_mask(cpf), email, gov_status,
                 now_iso() if gov_status == "validado" else None))
        # Log do titular: SEM nome completo e SEM CPF — só status (LGPD mínima)
        log_user_event(username, {"event": "registro", "ip": self.client_address[0],
                                   "device": device_os(self.headers.get("User-Agent", "")),
                                   "nome_social": is_social, "validacao_gov": gov_status})
        form["password"] = [password]
        return self.api_login(form)

    def api_login(self, form=None):
        form = form or self._form()
        username = (form.get("username") or [""])[0].strip()[:64]
        password = (form.get("password") or [""])[0]
        om = self._omada_params(form)
        ua = self.headers.get("User-Agent", "")
        with db() as c:
            user = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not user or not verify_password(password, user["pw_hash"]):
            log_user_event(username or "desconhecido", {"event": "login_falhou", "ip": self.client_address[0]})
            qs = urllib.parse.urlencode({k: v for k, v in om.items() if v})
            return self._redirect("/login?err=user&" + qs)
        token = secrets.token_urlsafe(32)
        with db() as c:
            c.execute("""INSERT INTO sessions(token,user_id,client_mac,client_ip,ap_mac,ssid_name,
                radio_id,device_os,is_apple,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (token, user["id"], om["clientMac"], om["clientIp"], om["apMac"], om["ssidName"],
                 om["radioId"], device_os(ua), int(detect_apple(ua)), now_iso(),
                 (datetime.now() + timedelta(minutes=CFG["session_duration_min"])).astimezone().isoformat(timespec="seconds")))
        log_user_event(username, {"event": "login_ok", "ip": self.client_address[0],
                                   "mac": om["clientMac"], "ap": om["apMac"], "device": device_os(ua)})
        return self._redirect("/pay?t=" + token)

    def api_pay_create(self):
        form = self._form()
        token = (form.get("t") or [""])[0]
        row = self._session(token)
        if not row:
            return self._json(403, {"error": "sessão inválida"})
        user = self._username(row["user_id"])
        amount = CFG["price_apple_brl_cents"] if row["is_apple"] else CFG["price_brl_cents"]
        with db() as c:
            pend = c.execute("""SELECT reference, checkout_url FROM payments
                                WHERE user_id=? AND status='pending' ORDER BY created_at DESC LIMIT 1""",
                             (row["user_id"],)).fetchone()
        if pend:
            try:
                pago, dados = livepix_check_payment(pend["reference"])
                if pago:
                    self._mark_paid(row, pend["reference"], dados)
                    return self._json(200, {"status": "paid"})
            except Exception as e:
                log_system(f"livepix check (reuso) falhou: {e!r}")
            if pend["checkout_url"]:
                return self._json(200, {"checkout": pend["checkout_url"], "reference": pend["reference"]})
        redir = f"{CFG['portal_public_base'].rstrip('/')}/pay?t={urllib.parse.quote(token)}"
        try:
            data = livepix_create_payment(amount, redir)
        except Exception as e:
            log_system(f"livepix create falhou: {e!r}")
            return self._json(502, {"error": "Não foi possível gerar o PIX agora. Tente novamente em instantes."})
        with db() as c:
            c.execute("""INSERT INTO payments(reference,user_id,client_mac,amount_cents,checkout_url,created_at)
                         VALUES(?,?,?,?,?,?)""",
                      (data["reference"], row["user_id"], row["client_mac"], amount,
                       data["redirectUrl"], now_iso()))
        log_user_event(user, {"event": "pix_gerado", "valor_cents": amount,
                              "reference": data["reference"], "device": row["device_os"]})
        return self._json(200, {"checkout": data["redirectUrl"], "reference": data["reference"]})

    def api_pay_simulate(self):
        """Simula pagamento para usuários de teste (PORTAL_TEST_USERS)."""
        form = self._form()
        token = (form.get("t") or [""])[0]
        row = self._session(token)
        if not row:
            return self._json(403, {"error": "sessão inválida"})
        user = self._username(row["user_id"])
        if not is_test_user(user):
            log_system(f"simulate negado para usuário não-teste ({self.client_address[0]})")
            return self._json(403, {"error": "não permitido"})
        amount = CFG["price_apple_brl_cents"] if row["is_apple"] else CFG["price_brl_cents"]
        ref = "TESTE-" + secrets.token_hex(8)
        with db() as c:
            c.execute("""INSERT INTO payments(reference,user_id,client_mac,amount_cents,checkout_url,created_at,status,paid_at,proof)
                         VALUES(?,?,?,?,?,?,?,?,?)""",
                      (ref, row["user_id"], row["client_mac"], amount, "", now_iso(), "paid", now_iso(),
                       json.dumps({"simulado": True})))
        log_user_event(user, {"event": "pagamento_simulado_teste", "reference": ref,
                              "valor_cents": amount, "device": row["device_os"]})
        ok = self._authorize(row, ref)
        return self._json(200, {"status": "authorized" if ok else "omada_error"})

    def api_check(self, q):
        token = (q.get("t") or [""])[0]
        row = self._session(token)
        if not row:
            return self._json(403, {"status": "invalid"})
        if row["authorized"]:
            try:
                exp = datetime.fromisoformat(row["expires_at"])
                venceu = datetime.now().astimezone() >= exp
            except Exception:
                venceu = False
            if venceu:
                try:
                    omada_deauth(row["client_mac"])
                except Exception as e:
                    log_system(f"deauth pos-expiracao falhou: {e!r}")
                with db() as c:
                    c.execute("UPDATE sessions SET authorized=0 WHERE token=?", (row["token"],))
                log_user_event(self._username(row["user_id"]) or "",
                               {"event": "sessao_expirada_desautorizado", "mac": row["client_mac"],
                                "expires_at": row["expires_at"]})
                return self._json(200, {"status": "expired"})
            return self._json(200, {"status": "authorized", "expires_at": row["expires_at"]})
        with db() as c:
            pay = c.execute("SELECT * FROM payments WHERE user_id=? ORDER BY created_at DESC LIMIT 1",
                            (row["user_id"],)).fetchone()
        if not pay:
            return self._json(200, {"status": "awaiting_payment"})
        if pay["status"] == "paid":
            ok = self._authorize(row, pay["reference"])
            return self._json(200, {"status": "authorized" if ok else "omada_error"})
        try:
            pago, dados = livepix_check_payment(pay["reference"])
        except Exception as e:
            log_system(f"livepix check falhou: {e!r}")
            return self._json(502, {"status": "check_error"})
        if pago:
            self._mark_paid(row, pay["reference"], dados, update_db=False)
            ok = self._authorize(row, pay["reference"])
            return self._json(200, {"status": "authorized" if ok else "omada_error"})
        return self._json(200, {"status": "awaiting_payment"})

    def api_status(self, q):
        token = (q.get("t") or [""])[0]
        row = self._session(token)
        if not row:
            return self._json(404, {"status": "none"})
        return self._json(200, {"authorized": bool(row["authorized"]), "expires_at": row["expires_at"],
                                "device": row["device_os"]})

    # ---- LGPD: titular ----
    def api_export_me(self, q):
        """Exporta todos os dados do titular (direito de acesso, LGPD art. 20)."""
        token = (q.get("t") or [""])[0]
        row = self._session(token)
        if not row:
            return self._json(403, {"error": "sessão inválida"})
        with db() as c:
            user = c.execute("SELECT id,username,created_at,consent_at,consent_ip FROM users WHERE id=?",
                             (row["user_id"],)).fetchone()
            pays = c.execute("""SELECT reference,amount_cents,status,created_at,paid_at
                                FROM payments WHERE user_id=?""", (row["user_id"],)).fetchall()
            sess = c.execute("""SELECT created_at,expires_at,authorized,device_os,client_ip
                                FROM sessions WHERE user_id=?""", (row["user_id"],)).fetchall()
        data = dict(user)
        data["pagamentos"] = [dict(p) for p in pays]
        data["sessoes"] = [dict(s) for s in sess]
        base = USERS_DIR / safe_name(user["username"])
        jl = str(base) + ".jsonl"
        data["eventos_log"] = ([json.loads(l) for l in open(jl, encoding="utf-8").read().splitlines()]
                               if Path(jl).exists() else [])
        self._send(200, json.dumps(data, ensure_ascii=False, indent=2), "application/json; charset=utf-8")

    def api_delete_me(self, q):
        """Exclusão total de dados do titular (direito de exclusão, LGPD art. 18)."""
        token = (q.get("t") or [""])[0]
        row = self._session(token)
        if not row:
            return self._json(403, {"error": "sessão inválida"})
        user = self._username(row["user_id"])
        with db() as c:
            c.execute("DELETE FROM users WHERE id=?", (row["user_id"],))
            c.execute("DELETE FROM sessions WHERE user_id=?", (row["user_id"],))
            c.execute("DELETE FROM payments WHERE user_id=?", (row["user_id"],))
        log_system(f"LGPD exclusão total do usuário {safe_name(user or 'anon')}")
        for suf in (".log", ".jsonl"):
            p = USERS_DIR / (safe_name(user) + suf)
            if p.exists():
                p.unlink()
        return self._json(200, {"status": "deleted"})

    # ---- helpers internos ----
    def _session(self, token):
        with db() as c:
            return c.execute("SELECT * FROM sessions WHERE token=?", (token,)).fetchone()

    def _username(self, uid):
        with db() as c:
            r = c.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
            return r["username"] if r else None

    def _mark_paid(self, row, reference, dados, update_db=True):
        if update_db:
            with db() as c:
                c.execute("UPDATE payments SET status='paid',paid_at=?,proof=? WHERE reference=?",
                          (now_iso(), json.dumps(dados, ensure_ascii=False), reference))
        user = self._username(row["user_id"])
        log_user_event(user, {"event": "pagamento_confirmado", "reference": reference,
                              "proof": dados.get("proof"), "valor_cents": dados.get("amount")})

    def _authorize(self, row, reference):
        """Autoriza cliente no Omada após confirmação de pagamento."""
        down = CFG["apple_rate_limit_kbps"] if row["is_apple"] else CFG["rate_limit_kbps"]
        try:
            ok, resp = omada_ext_portal_auth(
                client_mac=row["client_mac"], client_ip=row["client_ip"],
                ap_mac=row["ap_mac"], ssid_name=row["ssid_name"] or "NewsInside_Portal",
                radio_id=row["radio_id"],
                duration_min=CFG["session_duration_min"], down_kbps=down, up_kbps=down)
        except Exception as e:
            log_system(f"omada authorize falhou: {e!r}")
            return False
        expires = (datetime.now() + timedelta(minutes=CFG["session_duration_min"])).astimezone().isoformat(timespec="seconds")
        with db() as c:
            c.execute("UPDATE sessions SET authorized=1,authorized_at=?,expires_at=?,payment_ref=? WHERE token=?",
                      (now_iso(), expires, reference, row["token"]))
        user = self._username(row["user_id"])
        log_user_event(user, {"event": "autorizado_omada", "mac": row["client_mac"],
                              "rate_kbps": down, "duracao_min": CFG["session_duration_min"],
                              "omada_ok": ok})
        return ok


# ---------------------------------------------------------------------------
# Retenção e expiração (LGPD)
# ---------------------------------------------------------------------------
def retention_sweep():
    """Remove arquivos de log mais antigos que retention_days (LGPD)."""
    cutoff = datetime.now() - timedelta(days=CFG["retention_days"])
    removed = 0
    for f in USERS_DIR.glob("*"):
        try:
            if datetime.fromtimestamp(f.stat().st_mtime) < cutoff:
                f.unlink(); removed += 1
        except OSError:
            pass
    if removed:
        log_system(f"retenção LGPD: {removed} arquivos removidos")


def expiry_sweep():
    """Desautoriza no controller as sessões vencidas (mantém Omada e portal em sync)."""
    now = datetime.now().astimezone()
    with db() as c:
        rows = c.execute("SELECT token, user_id, client_mac, expires_at FROM sessions WHERE authorized=1").fetchall()
    for row in rows:
        try:
            if now >= datetime.fromisoformat(row["expires_at"]):
                try:
                    omada_deauth(row["client_mac"])
                except Exception as e:
                    log_system(f"deauth sweep {row['client_mac']}: {e!r}")
                with db() as c:
                    c.execute("UPDATE sessions SET authorized=0 WHERE token=?", (row["token"],))
                log_user_event(_username_static(row["user_id"]) or "",
                               {"event": "sessao_expirada_desautorizado", "mac": row["client_mac"],
                                "expires_at": row["expires_at"]})
        except Exception:
            continue


def _username_static(uid):
    with db() as c:
        r = c.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
        return r["username"] if r else None


def expiry_loop():
    """Loop em segundo plano que varre sessões expiradas a cada 60s."""
    while True:
        try:
            expiry_sweep()
        except Exception as e:
            log_system(f"expiry_sweep erro: {e!r}")
        time.sleep(60)


if __name__ == "__main__":
    retention_sweep()
    threading.Thread(target=expiry_loop, daemon=True).start()
    port = int(os.environ.get("PORTAL_PORT", CFG["portal_listen_port"]))
    srv = ThreadingHTTPServer(("0.0.0.0", port), PortalHandler)
    log_system(f"portal iniciado em 0.0.0.0:{port}")
    print(f"NewsInside_Portal rodando em 0.0.0.0:{port}")
    srv.serve_forever()
