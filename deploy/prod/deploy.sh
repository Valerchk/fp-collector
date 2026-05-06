#!/bin/bash
# Production deployment script for fp-collector
# Prerequisites: kubectl configured against your cluster, Docker logged in to your registry
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ── Config — edit these before running ──────────────────────────
REGISTRY="${REGISTRY:-}"          # e.g. docker.io/yourname or ghcr.io/yourname
IMAGE_TAG="${IMAGE_TAG:-latest}"
NAMESPACE="fp-collector"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/../../app" && pwd)"

[[ -z "$REGISTRY" ]] && error "Set REGISTRY before running.\n  Example: REGISTRY=docker.io/yourname bash deploy.sh"

IMAGE="$REGISTRY/fp-collector:$IMAGE_TAG"

# ── Step 1 — Build & push Docker image ──────────────────────────
info "1/6 — Building Docker image: $IMAGE"
docker build -t "$IMAGE" -f "$SCRIPT_DIR/Dockerfile" "$APP_DIR"
info "     Pushing..."
docker push "$IMAGE"
info "     Image pushed."

# ── Step 2 — Apply manifests (except secrets) ───────────────────
info "2/6 — Applying Kubernetes manifests..."
kubectl apply -f "$SCRIPT_DIR/00-namespace.yaml"

# Inject actual image name into 03-flask.yaml before applying
sed "s|REGISTRY/fp-collector:latest|$IMAGE|g" \
  "$SCRIPT_DIR/03-flask.yaml" | kubectl apply -f -

kubectl apply -f "$SCRIPT_DIR/01-crowdsec.yaml"
kubectl apply -f "$SCRIPT_DIR/02-traefik.yaml"
kubectl apply -f "$SCRIPT_DIR/05-nginx.yaml"

# ── Step 3 — Apply secrets (token must be set in 04-secrets.yaml) ──
info "3/6 — Checking secrets..."
if grep -q "REPLACE_WITH" "$SCRIPT_DIR/04-secrets.yaml"; then
  warn "04-secrets.yaml still has placeholder values."
  warn "Edit it with real tokens, then run:"
  warn "  kubectl apply -f deploy/prod/04-secrets.yaml"
else
  kubectl apply -f "$SCRIPT_DIR/04-secrets.yaml"
  info "     Secrets applied."
fi

# ── Step 4 — Wait for pods ──────────────────────────────────────
info "4/6 — Waiting for pods to be ready..."
kubectl wait --for=condition=ready pod -l app=crowdsec -n "$NAMESPACE" --timeout=120s || error "CrowdSec not ready"
kubectl wait --for=condition=ready pod -l app=traefik  -n "$NAMESPACE" --timeout=60s  || error "Traefik not ready"
kubectl wait --for=condition=ready pod -l app=flask    -n "$NAMESPACE" --timeout=120s || error "Flask not ready"
kubectl wait --for=condition=ready pod -l app=nginx    -n "$NAMESPACE" --timeout=60s  || error "Nginx not ready"
info "     All pods ready:"
kubectl get pods -n "$NAMESPACE"

# ── Step 5 — Generate CrowdSec bouncer API key ──────────────────
info "5/6 — Generating CrowdSec bouncer API key..."
BOUNCER_KEY=$(kubectl exec -n "$NAMESPACE" deploy/crowdsec -- \
  cscli bouncers add traefik-bouncer --output raw 2>/dev/null || true)

if [[ -z "$BOUNCER_KEY" ]]; then
  warn "Could not auto-generate key (bouncer may already exist)."
  warn "Run manually and paste into 04-secrets.yaml:"
  warn "  kubectl exec -n $NAMESPACE deploy/crowdsec -- cscli bouncers add traefik-bouncer"
else
  info "     Key generated. Patching ConfigMap..."
  # Inject key into the traefik-dynamic ConfigMap
  kubectl get configmap traefik-dynamic -n "$NAMESPACE" -o yaml \
    | sed "s/__CROWDSEC_KEY__/$BOUNCER_KEY/g" \
    | kubectl apply -f -
  # Restart Traefik to pick up the new config
  kubectl rollout restart deployment/traefik -n "$NAMESPACE"
  kubectl rollout status deployment/traefik -n "$NAMESPACE" --timeout=60s
  info "     Bouncer key injected and Traefik restarted."
fi

# ── Step 6 — Copy MaxMind DB into PVC (if not already there) ────
info "6/6 — Checking MaxMind GeoLite2-ASN database..."
MMDB_LOCAL="$APP_DIR/data/GeoLite2-ASN.mmdb"
if [[ -f "$MMDB_LOCAL" ]]; then
  FLASK_POD=$(kubectl get pod -n "$NAMESPACE" -l app=flask -o jsonpath='{.items[0].metadata.name}')
  kubectl cp "$MMDB_LOCAL" "$NAMESPACE/$FLASK_POD:/app/data/GeoLite2-ASN.mmdb"
  info "     MaxMind DB copied to pod."
else
  warn "GeoLite2-ASN.mmdb not found at $MMDB_LOCAL"
  warn "Download it and copy manually:"
  warn "  kubectl cp GeoLite2-ASN.mmdb $NAMESPACE/<flask-pod>:/app/data/GeoLite2-ASN.mmdb"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  fp-collector deployed to production!"
echo ""
echo "  Get external IP:  kubectl get svc traefik -n $NAMESPACE"
echo "  Flask logs:       kubectl logs -n $NAMESPACE -l app=flask -f"
echo "  CrowdSec logs:    kubectl logs -n $NAMESPACE -l app=crowdsec -f"
echo "════════════════════════════════════════════════════════════"
