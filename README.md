# fp-collector — Bot Detection & Fingerprint Collector

A phishing awareness tool that collects browser fingerprints and detects bots using reliable, hard-to-fake indicators. Detected bots are **blocked (HTTP 403)** and logged.

## Architecture

```
User / Bot
    │
    ▼
Traefik (reverse proxy) + CrowdSec (security engine)
    │
    ▼
Flask App (Python 3.13)
    ├── GET  /fp-collector/login/             → Login page + JS fingerprinting
    ├── POST /fp-collector/login/api/collect  → Receives fingerprint, detects bot
    ├── GET  /fp-collector/login/api/stats    → JSON statistics
    └── GET  /fp-collector/login/api/export   → CSV export
    │
    ▼
SQLite (visitors.db)
```

## Bot Detection Strategy

Detection relies on **hard indicators that cannot be faked**. Behavioral signals (mouse, scroll, keyboard) are collected for analysis but **do not trigger blocking** — they produce too many false positives.

### Hard indicators (→ block + log)

| Priority | Indicator | Why it's reliable |
|----------|-----------|-------------------|
| 1 | **Reverse DNS** (googlebot.com, amazonaws.com…) | IP cannot be spoofed in HTTP; verified with forward DNS |
| 2 | **Datacenter ASN** via MaxMind GeoLite2-ASN | ASN is tied to the IP block owner (Google, AWS, OVH…) |
| 3 | **Cloud IP ranges** (AWS + GCP, fetched live) | Fallback if MaxMind DB is missing |
| 4 | **Obvious User-Agent** (curl, wget, scrapy, googlebot…) | Trivial but catches most crawlers |
| 5 | **No JavaScript executed** | Real browsers always run JS |
| 6 | **No WebGL / No GPU** | Real browsers have GPU access |
| 7 | **Virtual GPU** (SwiftShader, LLVMpipe, VirtualBox…) | Software renderers = headless/VM |
| 8 | **GPU benchmark > 5000ms** | 1M gl.clear() ops: real GPU ~20ms, VM > 5000ms |
| 9 | **JS exec time < 5ms** | Headless browsers execute unnaturally fast |
| 10 | **hw_concurrency = 0** | Virtual machines report 0 CPU cores |

### Blocking behavior

- **GET /** — Early detection (IP + UA). Bot → **403 page** + log `[BLOCKED]`
- **POST /api/collect** — Full detection (JS + GPU + fingerprint). Bot → **403 JSON** + log `[BLOCKED]`
- **Human** → Normal page + log `[OK]` / `[ALLOWED]`

## Quick Start — Docker Compose

```bash
docker compose up -d

# Test — human (should return 200)
curl -s -o /dev/null -w "%{http_code}" http://localhost/fp-collector/login/

# Test — bot detection (should return 403)
curl -s -o /dev/null -w "%{http_code}" -A "curl/test" http://localhost/fp-collector/login/

# View logs (bot detections visible here)
docker compose logs flask -f

# Stats (requires token)
curl -H "Authorization: Bearer changeme" http://localhost/fp-collector/login/api/stats

# Export CSV (requires token)
curl -H "Authorization: Bearer changeme" http://localhost/fp-collector/login/api/export -o visitors.csv
```

## Deploy — Minikube (macOS)

### Prerequisites

- [Minikube](https://minikube.sigs.k8s.io/docs/start/) installed
- [kubectl](https://kubernetes.io/docs/tasks/tools/) installed
- Docker running

### Automated deployment

```bash
cd fp-collector
bash k8s/deploy.sh
```

The script will:
1. Start Minikube (if not running)
2. Mount the `app/` directory into the Minikube VM
3. Apply all Kubernetes manifests (namespace, CrowdSec, Traefik, Flask)
4. Wait for all pods to be ready
5. Start `minikube tunnel` for LoadBalancer access
6. Run smoke tests (human + bot)

To redeploy from scratch:
```bash
bash k8s/deploy.sh --clean
```

### Manual deployment

```bash
# 1. Start Minikube
minikube start

# 2. Mount app directory (keep this terminal open)
minikube mount ./app:/app

# 3. In another terminal — apply manifests
kubectl apply -f k8s/00-namespace.yaml
kubectl apply -f k8s/01-crowdsec.yaml
kubectl apply -f k8s/02-traefik.yaml
kubectl apply -f k8s/03-flask.yaml

# 4. Wait for pods
kubectl get pods -n fp-collector -w

# 5. Port-forward Traefik to localhost:8080
kubectl port-forward -n fp-collector svc/traefik 8080:80

# 6. Access the app (in another terminal)
curl http://127.0.0.1:8080/fp-collector/login/
```

### Viewing logs

```bash
# Flask logs — shows [BLOCKED] and [ALLOWED] for every request
kubectl logs -n fp-collector -l app=flask -f

# Traefik access logs
kubectl logs -n fp-collector -l app=traefik -f

# CrowdSec logs
kubectl logs -n fp-collector -l app=crowdsec -f
```

### Stopping

```bash
minikube stop
```

## Testing Bot Detection

All examples below use Docker Compose (`localhost` port 80). For Minikube, replace `localhost` with `127.0.0.1:**8080**` (after `kubectl port-forward`).

> **Tip:** Open a second terminal with logs **before** running tests so you can see detections in real time:
> ```bash
> # Docker Compose
> docker compose logs flask -f
>
> # Minikube
> kubectl logs -n fp-collector -l app=flask -f
> ```

### Test 1 — curl (obvious bot User-Agent)

curl sends its own UA (`curl/8.x`) which matches the `curl` pattern. Blocked at the GET level.

```bash
curl -v http://localhost/fp-collector/login/
```

**Expected:** HTTP `403`, body contains "Access Denied".
**Log output:**
```
[BLOCKED] ip=172.18.0.1 reason=obvious bot UA: curl asn= org= ua=curl/8.7.1
```

### Test 2 — Googlebot User-Agent

Simulates a Google crawler by spoofing the UA string.

```bash
curl -v -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" \
  http://localhost/fp-collector/login/
```

**Expected:** HTTP `403`.
**Log output:**
```
[BLOCKED] ip=172.18.0.1 reason=obvious bot UA: googlebot ...
```

### Test 3 — Google Safe Browsing UA

```bash
curl -v -A "Google-Safety" http://localhost/fp-collector/login/
```

**Expected:** HTTP `403`.
**Log output:**
```
[BLOCKED] ip=... reason=obvious bot UA: google-safety ...
```

### Test 4 — Python bot

```bash
curl -v -A "python-requests/2.31.0" http://localhost/fp-collector/login/
```

**Expected:** HTTP `403`.

### Test 5 — Headless browser (no interaction, virtual GPU)

Send a crafted POST to `/api/collect` simulating a headless browser with SwiftShader GPU:

```bash
# First, get a visitor_id by requesting the page with a normal UA
VISITOR_ID=$(curl -s -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120" \
  http://localhost/fp-collector/login/ | grep -o 'VISITOR_ID *= *[0-9]*' | grep -o '[0-9]*')

echo "visitor_id = $VISITOR_ID"

# Then send a fingerprint payload with a virtual GPU
curl -v -X POST http://localhost/fp-collector/login/api/collect \
  -H "Content-Type: application/json" \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120" \
  -d "{
    \"visitor_id\": $VISITOR_ID,
    \"js_enabled\": true,
    \"webgl_supported\": true,
    \"webgl_vendor\": \"Google Inc. (Google)\",
    \"webgl_renderer\": \"ANGLE (Google, Google SwiftShader, OpenGL ES)\",
    \"webgl_benchmark_ms\": 200,
    \"hw_concurrency\": 4,
    \"js_exec_time_ms\": 500,
    \"mouse_moves\": 0,
    \"scroll_events\": 0
  }"
```

**Expected:** HTTP `403`, `{"status":"blocked","is_bot":true}`.
**Log output:**
```
[BLOCKED] ip=... reason=virtual GPU: swiftshader renderer=ANGLE (Google, Google SwiftShader...) ...
```

### Test 6 — Slow GPU benchmark (VM detected)

Same as above but with a very slow GPU benchmark (>5000ms = virtual machine):

```bash
curl -v -X POST http://localhost/fp-collector/login/api/collect \
  -H "Content-Type: application/json" \
  -d "{
    \"visitor_id\": $VISITOR_ID,
    \"js_enabled\": true,
    \"webgl_supported\": true,
    \"webgl_vendor\": \"VMware\",
    \"webgl_renderer\": \"SVGA3D\",
    \"webgl_benchmark_ms\": 12000,
    \"hw_concurrency\": 2,
    \"js_exec_time_ms\": 800
  }"
```

**Expected:** HTTP `403`, reason = `GPU benchmark too slow: 12000ms (VM suspected)`.

### Test 7 — Real browser (human)

Open in a real browser (Chrome, Firefox, Safari):

```
http://localhost/fp-collector/login/
```

**Expected:** Login page loads normally (HTTP `200`). After 3 seconds, fingerprint is sent automatically. **Log output:**
```
[ALLOWED] ip=172.18.0.1 asn= org=
[OK] ip=172.18.0.1 gpu=ANGLE (Apple, Apple M2, OpenGL 4.1) benchmark=18ms mouse=12 scroll=3
```

### Test 8 — Check stats after all tests

```bash
curl -s http://localhost/fp-collector/login/api/stats | python3 -m json.tool
```

**Expected output (example):**
```json
{
    "total": 7,
    "bots": 6,
    "humans": 1,
    "no_js": 0,
    "datacenter": 0,
    "virtual_gpu": 1,
    "no_interaction": 0,
    "gpu_slow": 1
}
```

### Test 9 — Export CSV and inspect

```bash
curl -s http://localhost/fp-collector/login/api/export -o visitors.csv
cat visitors.csv | column -t -s,
```

Look at the `is_bot` and `bot_reason` columns to verify each detection.

### Test 10 — ASN detection (datacenter IPs)

Use `X-Forwarded-For` to simulate requests from known datacenter IPs. These should be blocked even with a normal browser UA...

```bash
# Google datacenter → 403
curl -v -A "Mozilla/5.0 Chrome/120" -H "X-Forwarded-For: 8.8.8.8" \
  http://localhost/fp-collector/login/

# AWS datacenter → 403
curl -v -A "Mozilla/5.0 Chrome/120" -H "X-Forwarded-For: 54.239.28.85" \
  http://localhost/fp-collector/login/

# Microsoft Azure → 403
curl -v -A "Mozilla/5.0 Chrome/120" -H "X-Forwarded-For: 20.190.128.1" \
  http://localhost/fp-collector/login/

# OVH hosting → 403
curl -v -A "Mozilla/5.0 Chrome/120" -H "X-Forwarded-For: 51.210.0.1" \
  http://localhost/fp-collector/login/

# French ISP (real user) → 200
curl -v -A "Mozilla/5.0 Chrome/120" -H "X-Forwarded-For: 86.238.1.1" \
  http://localhost/fp-collector/login/
```

**Expected:** Datacenter IPs → `403`. Residential ISP → `200`.
**Log output:**
```
[BLOCKED] ip=8.8.8.8 reason=datacenter ASN: Google LLC (AS15169) asn=AS15169 org=Google LLC ...
[BLOCKED] ip=54.239.28.85 reason=datacenter ASN: Amazon.com, Inc. (AS16509) asn=AS16509 org=Amazon.com, Inc. ...
[ALLOWED] ip=86.238.1.1 asn=AS3215 org=Orange
```

> **Note:** `X-Forwarded-For` tests require Traefik to trust the header (`forwardedHeaders.insecure=true` in K8s config). In production, this header is set by the real reverse proxy from the client's actual IP.

### Summary table

| Test | Method | What triggers detection | Expected HTTP |
|------|--------|------------------------|---------------|
| curl default | GET | UA matches `curl` | **403** |
| Googlebot UA | GET | UA matches `googlebot` | **403** |
| Google-Safety | GET | UA matches `google-safety` | **403** |
| python-requests | GET | UA matches `python-requests` | **403** |
| SwiftShader GPU | POST | Virtual GPU renderer | **403** |
| Slow GPU (VM) | POST | benchmark > 5000ms | **403** |
| Google IP (ASN) | GET | datacenter ASN: Google LLC | **403** |
| AWS IP (ASN) | GET | datacenter ASN: Amazon.com | **403** |
| OVH IP (ASN) | GET | datacenter ASN: OVH SAS | **403** |
| French ISP | GET | residential ISP (no match) | **200** |
| Real browser | GET+POST | Nothing triggers | **200** |

---

## MaxMind GeoLite2-ASN 

MaxMind provides the most reliable datacenter/ASN detection. Without it, the app falls back to cloud IP range matching (less accurate).

1. Thanks to this repo https://github.com/P3TERX/GeoLite.mmdb?tab=readme-ov-file you can download the GeoLite.mmdb file, once it;s done
2. Place it in `app/data/GeoLite2-ASN.mmdb`
3. Restart the app

## Project Structure

```
fp-collector/
├── app/
│   ├── app.py                ← Flask backend + bot blocking
│   ├── bot_detection.py      ← Detection logic (reverse DNS, ASN, cloud IP)
│   ├── requirements.txt      ← flask, geoip2
│   ├── data/
│   │   ├── visitors.db       ← SQLite database (auto-created)
│   │   └── GeoLite2-ASN.mmdb ← MaxMind DB (manual download)
│   └── templates/
│       └── index.html        ← Login page + JS fingerprinting
├── docker-compose.yml        ← Docker Compose (Traefik + CrowdSec + Flask)
├── traefik/
│   └── dynamic.yml           ← CrowdSec bouncer middleware config
├── crowdsec/
│   └── acquis.yml            ← CrowdSec log acquisition config
└── k8s/
    ├── 00-namespace.yaml     ← Kubernetes namespace
    ├── 01-crowdsec.yaml      ← CrowdSec deployment + service
    ├── 02-traefik.yaml       ← Traefik deployment + RBAC + LoadBalancer
    ├── 03-flask.yaml         ← Flask deployment + service + ingress
    └── deploy.sh             ← Automated Minikube deployment script
```

## API Authentication

The `/api/stats` and `/api/export` endpoints require a Bearer token. Set the token via the `API_TOKEN` environment variable (default: `changeme`).

```bash
# Stats
curl -H "Authorization: Bearer changeme" http://localhost/fp-collector/login/api/stats

# Export CSV
curl -H "Authorization: Bearer changeme" http://localhost/fp-collector/login/api/export -o visitors.csv

# Without token → 401 Unauthorized
curl http://localhost/fp-collector/login/api/stats
```

For production, set a strong token:
```bash
# Docker Compose
API_TOKEN=my-secret-token-here docker compose up -d

# Minikube — edit k8s/03-flask.yaml, change API_TOKEN value
```