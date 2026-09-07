#!/usr/bin/env bash
# Helm install auth-service into DOKS preprod using CarCatApp/charts (carcat-app).
# Does NOT touch the production droplet.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SECRETS_DIR="${CARCAT_SECRETS_DIR:-$HOME/Documents/carcat_tech/.secrets}"
export KUBECONFIG="${KUBECONFIG:-$SECRETS_DIR/kubeconfig-carcat.yaml}"

NS="preprod"
RELEASE="auth-service"
CHART_REF="${CHART_REF:-https://github.com/CarCatApp/charts/archive/refs/tags/carcat-app-0.1.1.tar.gz}"
# Local fallback while developing chart:
# CHART_REF="$HOME/Documents/carcat_tech/charts/carcat-app"

IMAGE_TAG="${IMAGE_TAG:-latest}"

if ! kubectl -n "$NS" get secret auth-service-env >/dev/null 2>&1; then
  echo "Missing secret auth-service-env — run ./deploy/install-secret-preprod.sh first" >&2
  exit 1
fi

# Prefer local chart if present (dev); else tagged GitHub archive
if [[ -d "${CARCAT_CHARTS_DIR:-$HOME/Documents/carcat_tech/charts}/carcat-app" ]]; then
  CHART_PATH="${CARCAT_CHARTS_DIR:-$HOME/Documents/carcat_tech/charts}/carcat-app"
else
  CHART_PATH="$CHART_REF"
fi

echo "==> helm upgrade --install $RELEASE (ns=$NS, tag=$IMAGE_TAG)"
helm upgrade --install "$RELEASE" "$CHART_PATH" \
  --namespace "$NS" \
  -f "$SCRIPT_DIR/values.yaml" \
  -f "$SCRIPT_DIR/values-preprod.yaml" \
  --set "image.tag=$IMAGE_TAG" \
  --wait --timeout 10m

kubectl -n "$NS" get pods,svc -l app.kubernetes.io/name=auth-service
echo "Kong route /server → auth-service.preprod.svc:9090"
