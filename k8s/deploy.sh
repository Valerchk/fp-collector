set -e

# Usage:
#   cd gottaphish
#   bash k8s/deploy.sh          # deploy everything
#   bash k8s/deploy.sh --clean  # delete namespace and redeploy
# ─────────────────────────────────────────────────────────────────

APP_DIR="$(cd "$(dirname "$0")/.." && pwd)/app"
BASE_URL="/gottaphish/part2/login/"
NAMESPACE="gottaphish"
LOCAL_PORT=8080

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ── Clean up if --clean ──
if [[ "$1" == "--clean" ]]; then
    warn "Deleting namespace $NAMESPACE..."
    kubectl delete namespace "$NAMESPACE" --ignore-not-found 2>/dev/null || true
    kubectl delete clusterrole traefik --ignore-not-found 2>/dev/null || true
    kubectl delete clusterrolebinding traefik --ignore-not-found 2>/dev/null || true
    kubectl delete ingressclass traefik --ignore-not-found 2>/dev/null || true
    sleep 3
fi

# ── 1. Check / start Minikube ──
info "1/6 — Checking Minikube..."
if ! minikube status --format='{{.Host}}' 2>/dev/null | grep -q Running; then
    info "Starting Minikube..."
    minikube start
fi

# ── 2. Mount app directory into Minikube VM ──
info "2/6 — Mounting app/ into Minikube..."
info "  Source: $APP_DIR"
info "  Target: /app (inside Minikube VM)"

# Kill any existing mount
pkill -f "minikube mount.*:/app" 2>/dev/null || true
sleep 1

minikube mount "$APP_DIR:/app" &
MOUNT_PID=$!
sleep 3

if ! kill -0 "$MOUNT_PID" 2>/dev/null; then
    error "Mount failed. Check that $APP_DIR exists."
fi
info "  Mount OK (PID $MOUNT_PID)"

# ── 3. Apply manifests ──
info "3/6 — Applying Kubernetes manifests..."
kubectl apply -f k8s/00-namespace.yaml
kubectl apply -f k8s/01-crowdsec.yaml
kubectl apply -f k8s/02-traefik.yaml
kubectl apply -f k8s/03-flask.yaml

# ── 4. Wait for pods ──
info "4/6 — Waiting for pods..."
kubectl wait --for=condition=ready pod -l app=crowdsec -n "$NAMESPACE" --timeout=120s 2>/dev/null || warn "CrowdSec not ready (timeout — non-blocking)"
kubectl wait --for=condition=ready pod -l app=traefik  -n "$NAMESPACE" --timeout=60s  || error "Traefik not ready"
kubectl wait --for=condition=ready pod -l app=flask    -n "$NAMESPACE" --timeout=120s || error "Flask not ready"

info "  All pods ready:"
kubectl get pods -n "$NAMESPACE"

# ── 5. Port-forward Traefik to localhost ──
info "5/6 — Setting up port-forward (Traefik → localhost:$LOCAL_PORT)..."
pkill -f "kubectl port-forward.*svc/traefik" 2>/dev/null || true
sleep 1

kubectl port-forward -n "$NAMESPACE" svc/traefik "$LOCAL_PORT:80" &>/dev/null &
PF_PID=$!
sleep 2

if ! kill -0 "$PF_PID" 2>/dev/null; then
    error "Port-forward failed."
fi
info "  Port-forward OK (PID $PF_PID)"

# ── 6. Smoke tests ──
info "6/6 — Running smoke tests..."
echo ""

APP_URL="http://127.0.0.1:${LOCAL_PORT}${BASE_URL}"

# Test 1: real browser UA → should be 200
info "Test: human visitor (normal UA)..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 \
  -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36" \
  "$APP_URL" 2>/dev/null || echo "000")
if [[ "$HTTP_CODE" == "200" ]]; then
    info "  Human:  ${GREEN}HTTP $HTTP_CODE OK${NC}"
else
    warn "  Human:  HTTP $HTTP_CODE (expected 200 — check logs)"
fi

# Test 2: curl UA → should be 403
info "Test: bot visitor (curl UA)..."
BOT_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 \
  -A "curl/8.0" \
  "$APP_URL" 2>/dev/null || echo "000")
if [[ "$BOT_CODE" == "403" ]]; then
    info "  Bot:    ${GREEN}HTTP $BOT_CODE BLOCKED${NC}"
else
    warn "  Bot:    HTTP $BOT_CODE (expected 403 — check logs)"
fi

# Test 3: Googlebot UA → should be 403
info "Test: Googlebot..."
GBOT_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 \
  -A "Mozilla/5.0 (compatible; Googlebot/2.1)" \
  "$APP_URL" 2>/dev/null || echo "000")
if [[ "$GBOT_CODE" == "403" ]]; then
    info "  Google: ${GREEN}HTTP $GBOT_CODE BLOCKED${NC}"
else
    warn "  Google: HTTP $GBOT_CODE (expected 403 — check logs)"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Gottaphish deployed successfully!"
echo ""
echo "  App:        $APP_URL"
echo "  Stats:      ${APP_URL}api/stats"
echo "  Export CSV: ${APP_URL}api/export"
echo ""
echo "  View logs (open another terminal):"
echo "    kubectl logs -n $NAMESPACE -l app=flask -f"
echo ""
echo "  To stop:"
echo "    kill $MOUNT_PID $PF_PID"
echo "    minikube stop"
echo "════════════════════════════════════════════════════════════"
