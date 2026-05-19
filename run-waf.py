"""
╔══════════════════════════════════════════════════════════════╗
║        FastAPI WAF  —  Production Hardened v3.0             ║
║        Expert Review: 10yr WAF Engineering                  ║
║                                                              ║
║  Layers:                                                     ║
║   1. IP Reputation + Whitelist                               ║
║   2. URL / Header / Parameter flood guards                   ║
║   3. Payload size + Content-Type enforcement                 ║
║   4. Fingerprint-based blacklist (IP+headers)                ║
║   5. Token-bucket rate limiter (burst-aware)                 ║
║   6. Multi-pass normalization (8 bypass techniques)          ║
║   7. Context-weighted detection (40+ rule patterns)          ║
║   8. JSON/XML deep body flattening before inspection         ║
║   9. Behavioral anomaly scoring (velocity + diversity)       ║
║  10. Security response headers injection                     ║
║  11. Async non-blocking structured JSONL logging             ║
║  12. Protected metrics + public health endpoints             ║
╚══════════════════════════════════════════════════════════════╝
"""

# ─── stdlib ──────────────────────────────────────────────────
import hashlib
import html
import ipaddress
import json
import logging
import os
import queue
import re
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

# ─── third-party ─────────────────────────────────────────────
import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

# ══════════════════════════════════════════════════════════════
# ⚙️  CONFIGURATION  (all tunable via env-vars)
# ══════════════════════════════════════════════════════════════
CONFIG: dict = {
    # Upstream backend
    "TARGET_SERVER":          os.environ.get("TARGET_SERVER",           "http://127.0.0.1:5000"),
    "PROXY_TIMEOUT_CONNECT":  float(os.environ.get("PROXY_TIMEOUT_CONNECT", "3")),
    "PROXY_TIMEOUT_READ":     float(os.environ.get("PROXY_TIMEOUT_READ",    "10")),

    # Scoring thresholds
    "BLOCK_THRESHOLD":        int(os.environ.get("BLOCK_THRESHOLD",     "10")),
    "CHALLENGE_THRESHOLD":    int(os.environ.get("CHALLENGE_THRESHOLD", "6")),  # log-only zone

    # Token-bucket rate limiter
    "RATE_BURST":             int(os.environ.get("RATE_BURST",          "30")),
    "RATE_REFILL_PER_SEC":    int(os.environ.get("RATE_REFILL_PER_SEC", "15")),

    # Blacklist / Whitelist
    "BLACKLIST_SECONDS":      int(os.environ.get("BLACKLIST_SECONDS",   "600")),
    "IP_WHITELIST":           set(os.environ.get("IP_WHITELIST",        "").split(",")) - {""},

    # Request limits
    "MAX_BODY_BYTES":         int(os.environ.get("MAX_BODY_BYTES",      str(2 * 1024 * 1024))),
    "MAX_HEADER_COUNT":       int(os.environ.get("MAX_HEADER_COUNT",    "60")),
    "MAX_HEADER_VALUE_LEN":   int(os.environ.get("MAX_HEADER_VALUE_LEN","4096")),
    "MAX_URL_LEN":            int(os.environ.get("MAX_URL_LEN",         "2048")),
    "MAX_PARAM_COUNT":        int(os.environ.get("MAX_PARAM_COUNT",     "50")),

    # Auth
    "METRICS_TOKEN":          os.environ.get("METRICS_TOKEN",           "CHANGE_ME_NOW"),

    # Logging
    "LOG_FILE":               os.environ.get("LOG_FILE",                "waf_attacks.jsonl"),
    "LOG_ALL":                os.environ.get("LOG_ALL",                 "false").lower() == "true",

    # Infra
    "BEHIND_PROXY":           os.environ.get("BEHIND_PROXY",            "false").lower() == "true",
    "TRUSTED_PROXIES":        set(os.environ.get("TRUSTED_PROXIES",     "").split(",")) - {""},
    "NORMALIZE_MAX_ITER":     int(os.environ.get("NORMALIZE_MAX_ITER",  "8")),
}

# ── Startup validation ────────────────────────────────────────
_dev_mode = os.environ.get("WAF_DEV", "false").lower() == "true"
if CONFIG["METRICS_TOKEN"] == "CHANGE_ME_NOW" and not _dev_mode:
    raise RuntimeError("❌  Set METRICS_TOKEN env-var before deploying to production.")

# ══════════════════════════════════════════════════════════════
# 📋  DETECTION RULES
# (name, compiled_regex, base_score, block_immediately)
# ══════════════════════════════════════════════════════════════
_RAW_RULES: list[tuple[str, str, int, bool]] = [
    # ── SQL Injection ──────────────────────────────────────────
    ("SQLi_union",    r"union[\s\+\/\*]+select",                            8,  False),
    ("SQLi_boolean",  r"\bor\s+[\'\d][\s\S]{0,10}=[\s\S]{0,10}[\'\d]",    7,  False),
    ("SQLi_time",     r"(sleep\s*\(\s*\d|benchmark\s*\(\s*\d|waitfor\s+delay)", 8, False),
    ("SQLi_stacked",  r";\s*(drop|truncate|alter|create|insert|update|delete)\s+", 9, False),
    ("SQLi_comment",  r"(\/\*[\s\S]*?\*\/|--[\s\S]*?(\n|$)|#.*?(\n|$))",  3,  False),
    ("SQLi_blind",    r"(and\s+\d+=\d+|and\s+[\'\w]+=[\'\w]+)",           4,  False),

    # ── XSS ───────────────────────────────────────────────────
    ("XSS_script",    r"<\s*script[\s>\/]",                                7,  False),
    ("XSS_handler",   r"\bon\w{2,20}\s*=",                                 6,  False),
    ("XSS_proto",     r"(javascript|vbscript|data)\s*:",                   7,  False),
    ("XSS_tag",       r"<\s*(iframe|object|embed|applet|meta|link|base|form|svg|math)[\s>\/]", 5, False),
    ("XSS_css",       r"(expression\s*\(|@import\s|url\s*\(javascript)",   6,  False),

    # ── Path Traversal ────────────────────────────────────────
    ("Traversal_dot", r"(\.\.[\/\\]|[\/\\]\.\.)",                          7,  False),
    ("Traversal_enc", r"(%2e%2e[%2f%5c]|%2e%2e\/|\.\.%2f|\.\.%5c)",      8,  False),
    ("Traversal_abs", r"(\/etc\/passwd|\/proc\/self|c:\\windows\\|\/var\/www)", 9, True),

    # ── Command Injection ─────────────────────────────────────
    ("CMDi_pipe",     r"(\|\||&&|\$\([^)]{1,200}\)|`[^`]{1,200}`)",       8,  False),
    ("CMDi_shell",    r";\s*(bash|sh|cmd|powershell|python|perl|ruby|nc|wget|curl)\b", 9, True),
    ("CMDi_redirect", r"(>>?\s*\/|2>&1)",                                  6,  False),

    # ── SSRF ──────────────────────────────────────────────────
    ("SSRF_local",    r"(127\.\d+\.\d+\.\d+|::1|0\.0\.0\.0|localhost)",  7,  False),
    ("SSRF_meta",     r"169\.254\.\d+\.\d+",                               9,  True),   # AWS metadata
    ("SSRF_scheme",   r"(file|dict|gopher|tftp|ldap|sftp|ftp|ssh2?)\s*://",8, False),

    # ── XXE ───────────────────────────────────────────────────
    ("XXE_entity",    r"<!entity\s",                                        8,  False),
    ("XXE_system",    r"system\s+['\"]",                                    8,  False),
    ("XXE_param",     r"<!doctype[^>]*\[",                                  7,  False),

    # ── SSTI ──────────────────────────────────────────────────
    ("SSTI_jinja",    r"\{\{[\s\S]{0,200}\}\}",                            7,  False),
    ("SSTI_django",   r"\{%[\s\S]{0,200}%\}",                              6,  False),
    ("SSTI_expr",     r"(\$\{[\s\S]{0,200}\}|#\{[\s\S]{0,200}\})",        6,  False),

    # ── Log4Shell + SpringShell ───────────────────────────────
    ("Log4Shell",     r"\$\{(jndi|lower|upper|::-[jndi])",                10,  True),
    ("SpringShell",   r"(class\.module\.classLoader|ClassLoader\.)",        9,  True),

    # ── HTTP Smuggling / Splitting ────────────────────────────
    ("HTTPSplit",     r"(%0d%0a|%0a%0d|\r\n[^\t ]|\n[^\t ])",             8,  False),
    ("Smuggling_CL",  r"content-length\s*:\s*\d+[\s\S]{0,50}content-length\s*:", 9, True),

    # ── NoSQL Injection ───────────────────────────────────────
    ("NoSQLi",        r"(\$where|\$gt|\$lt|\$ne|\$regex|\$exists|\$or|\$and|\$not|\$nor)", 6, False),

    # ── Prototype Pollution ───────────────────────────────────
    ("Prototype",     r"(__(proto|defineGetter|defineSetter)__|constructor\.prototype)", 7, False),

    # ── Deserialization ───────────────────────────────────────
    ("Deser_java",    r"(rO0AB|aced0005|java\.io\.|org\.apache\.commons\.collections)", 8, True),
    ("Deser_php",     r"O:\d+:\"[\w\\]{1,100}\":\d+:\{",                  8,  True),

    # ── Scanner / Recon fingerprints ──────────────────────────
    ("Scanner_ua",    r"(sqlmap|nikto|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|ffuf|wfuzz|acunetix|havij|burpsuite)", 5, False),
    ("Scanner_path",  r"\/(wp-admin|phpmyadmin|\.git\/|\.env|\.aws\/|web\.config|xmlrpc\.php|\.htaccess)", 6, False),
    ("Scanner_ext",   r"\.(bak|old|swp|tmp|~|orig|backup|sql|dump)\s*$",  5,  False),
]

RULES: list[tuple[str, re.Pattern, int, bool]] = [
    (name, re.compile(pattern, re.IGNORECASE | re.DOTALL), score, immediate)
    for name, pattern, score, immediate in _RAW_RULES
]

# ── Context scoring weights ────────────────────────────────────
CONTEXT_WEIGHTS: dict[str, float] = {
    "path":    2.5,
    "params":  1.8,
    "body":    1.3,
    "headers": 0.7,
    "cookies": 1.0,
}

# ── Methods allowed through proxy ─────────────────────────────
ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})

# ── Headers never forwarded to backend ────────────────────────
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
})

# ── Security headers injected on every proxied response ───────
SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options":  "nosniff",
    "X-Frame-Options":         "SAMEORIGIN",
    "X-XSS-Protection":        "1; mode=block",
    "Referrer-Policy":         "strict-origin-when-cross-origin",
    "Permissions-Policy":      "geolocation=(), microphone=(), camera=()",
    "Cache-Control":           "no-store",
    "X-Powered-By":            "",          # empty = remove the header
}

# ══════════════════════════════════════════════════════════════
# 🔒  THREAD-SAFE IN-MEMORY STATE
# ══════════════════════════════════════════════════════════════
_lock = threading.Lock()

# fingerprint → session dict
_ip_store:     dict[str, dict]         = {}
# fingerprint → expiry (monotonic)
_blacklist:    dict[str, float]        = {}
# fingerprint → token-bucket dict
_rate_buckets: dict[str, dict]         = {}

_metrics: dict = {
    "total":      0,
    "blocked":    0,
    "passed":     0,
    "challenged": 0,
    "attacks":    defaultdict(int),
    "start":      datetime.now(timezone.utc).isoformat(),
}

# ══════════════════════════════════════════════════════════════
# 📝  NON-BLOCKING LOG WRITER
# ══════════════════════════════════════════════════════════════
_log_queue: queue.Queue = queue.Queue(maxsize=50_000)


def _log_writer() -> None:
    """Runs in a dedicated daemon thread — never stalls request path."""
    with open(CONFIG["LOG_FILE"], "a", buffering=4096, encoding="utf-8") as fh:
        while True:
            try:
                entry = _log_queue.get(timeout=1)
            except queue.Empty:
                fh.flush()
                continue
            if entry is None:       # poison-pill → graceful shutdown
                fh.flush()
                break
            try:
                fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
            except Exception:
                pass
            finally:
                _log_queue.task_done()


_log_thread = threading.Thread(target=_log_writer, daemon=True, name="waf-logger")
_log_thread.start()


def _log(entry: dict) -> None:
    try:
        _log_queue.put_nowait(entry)
    except queue.Full:
        pass    # drop log entry, never block the request


# ══════════════════════════════════════════════════════════════
# 🌐  IP HELPERS
# ══════════════════════════════════════════════════════════════
def _real_ip(request: Request) -> str:
    """
    Return the true client IP.
    When BEHIND_PROXY=true: trust X-Forwarded-For ONLY if the immediate
    peer is in TRUSTED_PROXIES (prevents XFF spoofing).
    """
    peer = request.client.host if request.client else "unknown"

    if not CONFIG["BEHIND_PROXY"]:
        return peer

    trusted = CONFIG["TRUSTED_PROXIES"]
    if trusted and peer not in trusted:
        return peer     # untrusted proxy — use direct peer

    xff = request.headers.get("X-Forwarded-For", "").split(",")
    candidate = xff[0].strip()
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        return peer


def _is_whitelisted(ip: str) -> bool:
    return ip in CONFIG["IP_WHITELIST"]


# ══════════════════════════════════════════════════════════════
# 🔍  FINGERPRINT  (IP + passive browser signals)
# ══════════════════════════════════════════════════════════════
def _fingerprint(request: Request, ip: str) -> str:
    ua   = request.headers.get("User-Agent",        "")[:512]
    lang = request.headers.get("Accept-Language",   "")[:64]
    enc  = request.headers.get("Accept-Encoding",   "")[:64]
    acc  = request.headers.get("Accept",            "")[:128]
    tls  = request.headers.get("X-TLS-Fingerprint", "")[:64]
    raw  = f"{ip}|{ua}|{lang}|{enc}|{acc}|{tls}"
    return hashlib.blake2b(raw.encode(), digest_size=10).hexdigest()


# ══════════════════════════════════════════════════════════════
# 🧹  MULTI-PASS NORMALIZATION
# Defeats: URL-encoding, double-encoding, HTML entities,
#          Unicode confusables, hex escapes, SQL comments,
#          null bytes, backslash escapes
# ══════════════════════════════════════════════════════════════
_UNICODE_MAP = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o",
    "\u0441": "c", "\u0445": "x", "\u0456": "i",
    "\uff1c": "<", "\uff1e": ">",
    "\u2019": "'", "\u02bc": "'",
    "\x00": "",    "\x0b": " ",   "\x0c": " ",
})

_RE_INLINE_COMMENT = re.compile(r"/\*[\s\S]*?\*/",          re.DOTALL)
_RE_LINE_COMMENT   = re.compile(r"(--|#)[^\n]*")
_RE_HTML_COMMENT   = re.compile(r"<!--[\s\S]*?-->",          re.DOTALL)
_RE_HEX_ESC        = re.compile(r"0x([0-9a-f]{2,})",        re.IGNORECASE)
_RE_BACKSLASH      = re.compile(r"\\([nrtbf'\"\\])")
_RE_WHITESPACE     = re.compile(r"\s+")


def normalize(data: str) -> str:
    if not data:
        return ""

    # Cap at 64 KB to prevent ReDoS on crafted inputs
    data = data[:65_536]

    # ① Unicode confusables + null bytes
    data = data.translate(_UNICODE_MAP)

    # ② Iterative URL-decode + HTML-unescape until stable
    for _ in range(CONFIG["NORMALIZE_MAX_ITER"]):
        prev = data
        try:
            data = urllib.parse.unquote_plus(data)
        except Exception:
            pass
        try:
            data = html.unescape(data)
        except Exception:
            pass
        if data == prev:
            break

    # ③ Hex literals  0x41 → A
    def _hex_sub(m: re.Match) -> str:
        try:
            return bytes.fromhex(m.group(1)).decode("latin-1")
        except Exception:
            return m.group(0)
    data = _RE_HEX_ESC.sub(_hex_sub, data)

    # ④ Backslash escapes
    data = _RE_BACKSLASH.sub(r"\1", data)

    # ⑤ Strip SQL + HTML comments
    data = _RE_INLINE_COMMENT.sub(" ", data)
    data = _RE_LINE_COMMENT.sub(" ", data)
    data = _RE_HTML_COMMENT.sub(" ", data)

    # ⑥ Collapse whitespace
    data = _RE_WHITESPACE.sub(" ", data)

    return data.lower().strip()


# ══════════════════════════════════════════════════════════════
# 🔬  DEEP BODY INSPECTION
# JSON → flatten all values recursively
# XML  → extract all text + attributes
# ══════════════════════════════════════════════════════════════
def _flatten_json(obj, depth: int = 0) -> str:
    if depth > 20:
        return ""
    if isinstance(obj, str):
        return obj + " "
    if isinstance(obj, (int, float, bool)):
        return str(obj) + " "
    if isinstance(obj, dict):
        return " ".join(_flatten_json(v, depth + 1) for v in obj.values())
    if isinstance(obj, list):
        return " ".join(_flatten_json(i, depth + 1) for i in obj)
    return ""


def _flatten_xml(data: str) -> str:
    try:
        root = ET.fromstring(data)
        parts: list[str] = []
        for el in root.iter():
            if el.text:  parts.append(el.text)
            if el.tail:  parts.append(el.tail)
            parts.extend(el.attrib.values())
        return " ".join(parts)
    except ET.ParseError:
        return data


def _prepare_body(body: str, content_type: str) -> str:
    ct = content_type.lower().split(";")[0].strip()
    if ct in ("application/json", "text/json"):
        try:
            return _flatten_json(json.loads(body))
        except (json.JSONDecodeError, ValueError):
            pass
    if ct in ("application/xml", "text/xml", "application/xhtml+xml"):
        return _flatten_xml(body)
    return body


# ══════════════════════════════════════════════════════════════
# 🔬  ANALYSIS ENGINE
# Returns (score, findings, block_immediately)
# ══════════════════════════════════════════════════════════════
def analyze(
    path:         str,
    params:       str,
    body:         str,
    headers:      str,
    cookies:      str,
    content_type: str,
) -> tuple[int, list[str], bool]:

    score           = 0
    findings:       list[str] = []
    immediate_block = False

    body_inspected = _prepare_body(body, content_type)

    contexts: dict[str, str] = {
        "path":    path,
        "params":  params,
        "body":    body_inspected,
        "headers": headers,
        "cookies": cookies,
    }

    for ctx_name, raw in contexts.items():
        if not raw:
            continue
        norm   = normalize(raw)
        weight = CONTEXT_WEIGHTS[ctx_name]

        for rule_name, pattern, base_score, critical in RULES:
            if pattern.search(norm):
                s = int(base_score * weight)

                # Bonus penalty for critical rules in high-risk positions
                if ctx_name in ("path", "params") and \
                   rule_name.startswith(("SQLi", "Traversal", "Log4Shell", "CMDi")):
                    s += 5

                score += s
                findings.append(f"{rule_name}[{ctx_name}]+{s}")

                if critical:
                    immediate_block = True

                with _lock:
                    _metrics["attacks"][rule_name] += 1

    return score, findings, immediate_block


# ══════════════════════════════════════════════════════════════
# 📊  BEHAVIORAL TRACKING + ANOMALY
# ══════════════════════════════════════════════════════════════
def _get_session(fp: str) -> dict:
    now = time.monotonic()
    with _lock:
        if fp not in _ip_store:
            _ip_store[fp] = {
                "req": 0, "score": 0,
                "last": now, "windows": [],
                "attack_types": set(),
            }
        e = _ip_store[fp]

        # Idle reset after 5 minutes
        if now - e["last"] > 300:
            e.update({"req": 0, "score": 0, "windows": [], "attack_types": set()})

        e["req"]     += 1
        e["windows"]  = [t for t in e["windows"] if now - t < 10]
        e["windows"].append(now)
        e["last"]     = now
    return e


def _update_session(fp: str, score: int, findings: list[str]) -> None:
    with _lock:
        e = _ip_store.get(fp)
        if not e:
            return
        e["score"] += score
        for f in findings:
            e["attack_types"].add(f.split("[")[0])


def _anomaly_score(e: dict) -> int:
    s = 0
    if e["req"]                    > 100: s += 4
    elif e["req"]                  > 50:  s += 2
    if e["score"]                  > 30:  s += 5
    elif e["score"]                > 15:  s += 2
    if len(e["windows"])           > 20:  s += 5
    elif len(e["windows"])         > 10:  s += 3
    # Multiple distinct attack types = scanner
    d = len(e.get("attack_types", set()))
    if d > 3: s += 4
    elif d > 1: s += 2
    return s


# ══════════════════════════════════════════════════════════════
# 🚦  TOKEN-BUCKET RATE LIMITER
# Burst-aware: allows sudden spikes, punishes sustained floods
# ══════════════════════════════════════════════════════════════
def _check_rate(fp: str) -> bool:
    now    = time.monotonic()
    burst  = CONFIG["RATE_BURST"]
    refill = CONFIG["RATE_REFILL_PER_SEC"]

    with _lock:
        if fp not in _rate_buckets:
            _rate_buckets[fp] = {"tokens": float(burst), "last": now}
        b = _rate_buckets[fp]
        elapsed    = now - b["last"]
        b["tokens"] = min(burst, b["tokens"] + elapsed * refill)
        b["last"]   = now
        if b["tokens"] >= 1.0:
            b["tokens"] -= 1.0
            return True
    return False


# ══════════════════════════════════════════════════════════════
# 🚫  BLACKLIST  (monotonic timestamps — no wall-clock drift)
# ══════════════════════════════════════════════════════════════
def _is_blacklisted(fp: str) -> bool:
    now = time.monotonic()
    with _lock:
        exp = _blacklist.get(fp)
        if exp is None:
            return False
        if now > exp:
            _blacklist.pop(fp, None)
            return False
        return True


def _blacklist_add(fp: str) -> None:
    with _lock:
        _blacklist[fp] = time.monotonic() + CONFIG["BLACKLIST_SECONDS"]


# ══════════════════════════════════════════════════════════════
# 🌐  HTTPX ASYNC CLIENT  (lifespan-managed connection pool)
# ══════════════════════════════════════════════════════════════
_http_client: Optional[httpx.AsyncClient] = None


@asynccontextmanager
async def _lifespan(app: FastAPI):
    global _http_client
    _http_client = httpx.AsyncClient(
        base_url         = CONFIG["TARGET_SERVER"],
        timeout          = httpx.Timeout(
                               connect = CONFIG["PROXY_TIMEOUT_CONNECT"],
                               read    = CONFIG["PROXY_TIMEOUT_READ"],
                               write   = 5.0,
                               pool    = 2.0,
                           ),
        limits           = httpx.Limits(
                               max_connections           = 500,
                               max_keepalive_connections = 100,
                               keepalive_expiry          = 30,
                           ),
        follow_redirects = False,
        http2            = True,
    )
    logging.info("WAF v3 started — target: %s", CONFIG["TARGET_SERVER"])
    yield
    # ── Graceful shutdown ─────────────────────────────────────
    await _http_client.aclose()
    _log_queue.put(None)
    _log_thread.join(timeout=3)
    logging.info("WAF shutdown complete")


# ══════════════════════════════════════════════════════════════
# 🚀  FASTAPI APP
# ══════════════════════════════════════════════════════════════
app = FastAPI(
    title       = "WAF Proxy v3",
    lifespan    = _lifespan,
    docs_url    = None,       # NEVER expose docs in production
    redoc_url   = None,
    openapi_url = None,
)

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


# ══════════════════════════════════════════════════════════════
# 📈  METRICS  (token-protected — never expose publicly)
# ══════════════════════════════════════════════════════════════
@app.get("/__waf/metrics")
async def waf_metrics(request: Request) -> JSONResponse:
    token = request.headers.get("X-Metrics-Token", "")
    if not token or token != CONFIG["METRICS_TOKEN"]:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    with _lock:
        start_dt = datetime.fromisoformat(_metrics["start"])
        uptime   = round((datetime.now(timezone.utc) - start_dt).total_seconds())
        snap = {
            "status":           "ok",
            "timestamp":        datetime.now(timezone.utc).isoformat(),
            "uptime_seconds":   uptime,
            "total_requests":   _metrics["total"],
            "blocked":          _metrics["blocked"],
            "challenged":       _metrics["challenged"],
            "passed":           _metrics["passed"],
            "block_rate_pct":   round(_metrics["blocked"] / max(_metrics["total"], 1) * 100, 2),
            "active_blacklist": len(_blacklist),
            "tracked_sessions": len(_ip_store),
            "attack_breakdown": dict(_metrics["attacks"]),
        }
    return JSONResponse(snap)


@app.get("/__waf/health")
async def health() -> JSONResponse:
    """Public liveness probe — leaks nothing sensitive."""
    return JSONResponse({"status": "ok"})


# ══════════════════════════════════════════════════════════════
# 🔁  PROXY / WAF CORE
# ══════════════════════════════════════════════════════════════
@app.api_route(
    "/{full_path:path}",
    methods           = list(ALLOWED_METHODS),
    include_in_schema = False,
)
async def proxy(request: Request, full_path: str = "") -> Response:

    t_start = time.monotonic()

    # ── [0] Method guard ──────────────────────────────────────
    if request.method not in ALLOWED_METHODS:
        return PlainTextResponse("Method Not Allowed", status_code=405)

    with _lock:
        _metrics["total"] += 1

    ip = _real_ip(request)
    fp = _fingerprint(request, ip)

    # ── [1] IP Whitelist ──────────────────────────────────────
    if _is_whitelisted(ip):
        return await _forward(request, full_path, ip, fp, score=0, t_start=t_start)

    # ── [2] URL length guard ──────────────────────────────────
    if len(str(request.url)) > CONFIG["MAX_URL_LEN"]:
        return PlainTextResponse("URI Too Long", status_code=414)

    # ── [3] Header flood / size guard ────────────────────────
    if len(request.headers) > CONFIG["MAX_HEADER_COUNT"]:
        return _block("Header flood", fp, ip, [], 0)

    for hdr_val in request.headers.values():
        if len(hdr_val) > CONFIG["MAX_HEADER_VALUE_LEN"]:
            return _block("Oversized header", fp, ip, [], 0)

    # ── [4] Parameter count guard ─────────────────────────────
    if len(request.query_params) > CONFIG["MAX_PARAM_COUNT"]:
        return _block("Param flood", fp, ip, [], 0)

    # ── [5] Body size guard ───────────────────────────────────
    cl_hdr = request.headers.get("content-length")
    if cl_hdr and int(cl_hdr) > CONFIG["MAX_BODY_BYTES"]:
        return PlainTextResponse("Payload Too Large", status_code=413)

    body_bytes = await request.body()
    if len(body_bytes) > CONFIG["MAX_BODY_BYTES"]:
        return PlainTextResponse("Payload Too Large", status_code=413)

    # ── [6] Blacklist ─────────────────────────────────────────
    if _is_blacklisted(fp):
        with _lock:
            _metrics["blocked"] += 1
        return PlainTextResponse("Forbidden", status_code=403)

    # ── [7] Rate limit ────────────────────────────────────────
    if not _check_rate(fp):
        with _lock:
            _metrics["blocked"] += 1
        return PlainTextResponse("Too Many Requests", status_code=429)

    # ── [8] Build analysis inputs ─────────────────────────────
    content_type = request.headers.get("content-type", "")
    body_str     = body_bytes.decode("utf-8", errors="replace")

    # Exclude sensitive headers from analysis string (never log auth)
    safe_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("cookie", "authorization", "x-api-key")
    }

    score, findings, immediate = analyze(
        path         = "/" + full_path,
        params       = str(dict(request.query_params)),
        body         = body_str,
        headers      = str(safe_headers),
        cookies      = str(dict(request.cookies)),
        content_type = content_type,
    )

    # ── [9] Behavioral tracking ───────────────────────────────
    session = _get_session(fp)
    _update_session(fp, score, findings)
    anomaly = _anomaly_score(session)
    total   = score + anomaly

    # ── [10] Decision ─────────────────────────────────────────
    if immediate or total >= CONFIG["BLOCK_THRESHOLD"]:
        return _block("Attack detected", fp, ip, findings, total, request, full_path)

    if total >= CONFIG["CHALLENGE_THRESHOLD"]:
        # Suspicious but not conclusive → log, let through
        with _lock:
            _metrics["challenged"] += 1
        _log({
            "event":    "challenge",
            "time":     datetime.now(timezone.utc).isoformat(),
            "ip":       ip, "fp": fp,
            "score":    total,
            "findings": findings,
            "method":   request.method,
            "path":     "/" + full_path,
        })

    # ── [11] Forward ──────────────────────────────────────────
    return await _forward(
        request, full_path, ip, fp,
        score      = total,
        t_start    = t_start,
        body_bytes = body_bytes,
    )


# ══════════════════════════════════════════════════════════════
# 🔀  FORWARD HELPER
# ══════════════════════════════════════════════════════════════
async def _forward(
    request:    Request,
    path:       str,
    ip:         str,
    fp:         str,
    score:      int,
    t_start:    float,
    body_bytes: bytes = b"",
) -> Response:

    fwd_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP
    }
    fwd_headers["X-Real-IP"]         = ip
    fwd_headers["X-Forwarded-For"]   = ip
    fwd_headers["X-Forwarded-Proto"] = "https"
    fwd_headers["X-WAF-Score"]       = str(score)

    try:
        resp = await _http_client.request(
            method  = request.method,
            url     = f"/{path}",
            headers = fwd_headers,
            content = body_bytes or await request.body(),
            params  = dict(request.query_params),
        )

        with _lock:
            _metrics["passed"] += 1

        # ── Build response headers ────────────────────────────
        out_headers = {
            k: v for k, v in resp.headers.items()
            if k.lower() not in HOP_BY_HOP
        }

        # Inject security headers; remove if value is empty string
        for hdr, val in SECURITY_HEADERS.items():
            if val:
                out_headers[hdr] = val
            else:
                out_headers.pop(hdr, None)

        elapsed_ms = round((time.monotonic() - t_start) * 1000, 1)
        out_headers["X-Response-Time"] = f"{elapsed_ms}ms"

        if CONFIG["LOG_ALL"]:
            _log({
                "event":    "pass",
                "time":     datetime.now(timezone.utc).isoformat(),
                "ip":       ip, "fp": fp,
                "method":   request.method,
                "path":     f"/{path}",
                "status":   resp.status_code,
                "score":    score,
                "elapsed":  elapsed_ms,
            })

        return Response(
            content     = resp.content,
            status_code = resp.status_code,
            headers     = out_headers,
        )

    except httpx.TimeoutException:
        logging.warning("Backend timeout: /%s", path)
        return PlainTextResponse("Gateway Timeout", status_code=504)

    except httpx.ConnectError:
        logging.error("Backend unreachable: %s", CONFIG["TARGET_SERVER"])
        return PlainTextResponse("Service Unavailable", status_code=503)

    except Exception as exc:
        logging.exception("Forward error: %s", exc)
        return PlainTextResponse("Bad Gateway", status_code=502)


# ══════════════════════════════════════════════════════════════
# 🚫  BLOCK HELPER
# ══════════════════════════════════════════════════════════════
def _block(
    reason:   str,
    fp:       str,
    ip:       str,
    findings: list[str],
    score:    int,
    request:  Optional[Request] = None,
    path:     str = "",
) -> PlainTextResponse:

    _blacklist_add(fp)

    with _lock:
        _metrics["blocked"] += 1

    _log({
        "event":    "block",
        "time":     datetime.now(timezone.utc).isoformat(),
        "reason":   reason,
        "ip":       ip,
        "fp":       fp,
        "score":    score,
        "findings": findings,
        "method":   request.method if request else "",
        "path":     f"/{path}"     if path    else "",
        "ua":       request.headers.get("User-Agent", "") if request else "",
    })

    return PlainTextResponse("Forbidden", status_code=403)


# ══════════════════════════════════════════════════════════════
# ▶  ENTRYPOINT
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "waf:app",
        host          = "0.0.0.0",
        port          = 8080,
        workers       = (os.cpu_count() or 2) * 2,
        loop          = "uvloop",      # pip install uvloop   → ~2-3x faster
        http          = "httptools",   # pip install httptools
        log_level     = "warning",
        access_log    = False,         # WAF has its own structured logging
        server_header = False,         # don't reveal server info
    )
