import csv
import os
import re
import sqlite3
from datetime import datetime

from flask import Flask, g, jsonify, render_template, request, send_file

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "data", "visitors.db")

# ---------------------------------------------------------------------------
# Known bot User-Agent patterns
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

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
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                ip               TEXT,
                user_agent       TEXT,
                accept_language  TEXT,
                js_enabled       INTEGER DEFAULT 0,
                fp_id            TEXT,
                canvas_hash      TEXT,
                webgl_vendor     TEXT,
                webgl_renderer   TEXT,
                webgl_supported  INTEGER DEFAULT 0,
                webgpu_supported INTEGER DEFAULT 0,
                screen           TEXT,
                timezone         TEXT,
                language         TEXT,
                platform         TEXT,
                hw_concurrency   INTEGER,
                device_memory    REAL,
                plugins_count    INTEGER,
                js_exec_time_ms  INTEGER,
                tls_cipher       TEXT,
                timestamp        TEXT,
                is_bot           INTEGER DEFAULT 0,
                bot_reason       TEXT
            )
        """)
        conn.commit()


# ---------------------------------------------------------------------------
# Bot detection
# ---------------------------------------------------------------------------

def ua_is_bot(ua: str):
    lower = ua.lower()
    for p in BOT_UA_PATTERNS:
        if re.search(p, lower):
            return True, f"UA match: {p}"
    return False, ""


def detect_bot(row: dict):
    # 1. User-Agent
    is_bot, reason = ua_is_bot(row.get("user_agent", ""))
    if is_bot:
        return True, reason

    # 2. No JS at all
    if not row.get("js_enabled"):
        return True, "no JS executed"

    # 3. No WebGL = no GPU
    if not row.get("webgl_supported"):
        return True, "no WebGL / no GPU"

    # 4. Virtual or software GPU
    renderer = (row.get("webgl_renderer") or "").lower()
    for hint in VIRTUAL_GPU:
        if hint in renderer:
            return True, f"virtual GPU: {hint}"

    # 5. JS too fast = headless
    t = row.get("js_exec_time_ms")
    if isinstance(t, (int, float)) and t < 5:
        return True, f"JS exec too fast ({t}ms)"

    # 6. No CPU cores reported
    if row.get("hw_concurrency") == 0:
        return True, "hw_concurrency=0"

    return False, ""


# ---------------------------------------------------------------------------
# Routes  —  all under /gottaphish/test1/
# ---------------------------------------------------------------------------

BASE = "/gottaphish/test1"


@app.route(f"{BASE}/")
def index():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ua = request.headers.get("User-Agent", "")
    accept_lang = request.headers.get("Accept-Language", "")
    tls_cipher = request.environ.get("SSL_CIPHER", "")
    ts = datetime.utcnow().isoformat()

    is_bot, bot_reason = ua_is_bot(ua)

    db = get_db()
    cur = db.execute("""
        INSERT INTO visitors
            (ip, user_agent, accept_language, tls_cipher, js_enabled, timestamp, is_bot, bot_reason)
        VALUES (?, ?, ?, ?, 0, ?, ?, ?)
    """, (ip, ua, accept_lang, tls_cipher, ts, int(is_bot), bot_reason))
    db.commit()

    return render_template("index.html", visitor_id=cur.lastrowid)


@app.route(f"{BASE}/api/collect", methods=["POST"])
def collect():
    data = request.get_json(silent=True) or {}
    visitor_id = data.get("visitor_id")
    if not visitor_id:
        return jsonify({"error": "missing visitor_id"}), 400

    row = {
        "user_agent":       request.headers.get("User-Agent", ""),
        "js_enabled":       1,
        "fp_id":            data.get("fp_id", ""),
        "canvas_hash":      data.get("canvas_hash", ""),
        "webgl_vendor":     data.get("webgl_vendor", ""),
        "webgl_renderer":   data.get("webgl_renderer", ""),
        "webgl_supported":  int(bool(data.get("webgl_supported"))),
        "webgpu_supported": int(bool(data.get("webgpu_supported"))),
        "screen":           data.get("screen", ""),
        "timezone":         data.get("timezone", ""),
        "language":         data.get("language", ""),
        "platform":         data.get("platform", ""),
        "hw_concurrency":   data.get("hw_concurrency", 0),
        "device_memory":    data.get("device_memory", 0),
        "plugins_count":    data.get("plugins_count", 0),
        "js_exec_time_ms":  data.get("js_exec_time_ms", 0),
    }

    is_bot, bot_reason = detect_bot(row)

    db = get_db()
    db.execute("""
        UPDATE visitors SET
            js_enabled       = 1,
            fp_id            = ?,
            canvas_hash      = ?,
            webgl_vendor     = ?,
            webgl_renderer   = ?,
            webgl_supported  = ?,
            webgpu_supported = ?,
            screen           = ?,
            timezone         = ?,
            language         = ?,
            platform         = ?,
            hw_concurrency   = ?,
            device_memory    = ?,
            plugins_count    = ?,
            js_exec_time_ms  = ?,
            is_bot           = ?,
            bot_reason       = ?
        WHERE id = ?
    """, (
        row["fp_id"], row["canvas_hash"],
        row["webgl_vendor"], row["webgl_renderer"],
        row["webgl_supported"], row["webgpu_supported"],
        row["screen"], row["timezone"], row["language"], row["platform"],
        row["hw_concurrency"], row["device_memory"],
        row["plugins_count"], row["js_exec_time_ms"],
        int(is_bot), bot_reason, visitor_id
    ))
    db.commit()

    return jsonify({"status": "ok", "is_bot": is_bot})


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
        "no_gpu":         count("webgl_supported=0 AND js_enabled=1"),
        "virtual_gpu":    count("bot_reason LIKE '%GPU%'"),
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
            "webgl_vendor", "webgl_renderer", "webgl_supported",
            "webgpu_supported", "screen", "timezone", "language",
            "platform", "hw_concurrency", "device_memory",
            "plugins_count", "js_exec_time_ms", "tls_cipher",
            "timestamp", "is_bot", "bot_reason"
        ])
        for row in rows:
            w.writerow(list(row))
    return send_file(path, mimetype="text/csv", as_attachment=True,
                     download_name="visitors_export.csv")


# ---------------------------------------------------------------------------

init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)