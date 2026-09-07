#!/usr/bin/env bash
# Create/update K8s secret auth-service-env in preprod from local files + optional droplet pull.
# Does NOT modify the production droplet.
set -euo pipefail

SECRETS_DIR="${CARCAT_SECRETS_DIR:-$HOME/Documents/carcat_tech/.secrets}"
export KUBECONFIG="${KUBECONFIG:-$SECRETS_DIR/kubeconfig-carcat.yaml}"
NS="preprod"
SECRET="auth-service-env"

PASS_JSON="$SECRETS_DIR/postgres_preprod_user_passwords.json"
if [[ ! -f "$PASS_JSON" ]]; then
  echo "Missing $PASS_JSON" >&2
  exit 1
fi
DB_PASS="$(python3 -c "import json; print(json.load(open('$PASS_JSON'))['auth'])")"

# Token secrets: prefer local file, else copy names from droplet once into .secrets
TOKENS_FILE="$SECRETS_DIR/auth_preprod_tokens.env"
if [[ ! -f "$TOKENS_FILE" ]]; then
  echo "==> fetching token keys from droplet into $TOKENS_FILE (one-time)"
  ssh -i "${SSH_KEY:-$HOME/.ssh/id_ed25519_carcat}" -o BatchMode=yes root@142.93.169.121 \
    'grep -E "^(ACCESS_TOKEN_SECRET_KEY|AUTHENTICATION_TOKEN_SECRET_KEY|REFRESH_TOKEN_SECRET_KEY)=" /root/carland.env' \
    > "$TOKENS_FILE" || true
  # fallback: extract from application.yaml defaults if grep empty — user must fill
  if [[ ! -s "$TOKENS_FILE" ]]; then
    echo "Fill $TOKENS_FILE with ACCESS_TOKEN_SECRET_KEY=... etc" >&2
    exit 1
  fi
  chmod 600 "$TOKENS_FILE"
fi

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

# Merge DB password into env file for a single --from-env-file (kubectl can't mix flags)
MERGED="$(mktemp)"
trap 'rm -f "$MERGED"' EXIT
grep -v '^SPRING_DATASOURCE_PASSWORD=' "$TOKENS_FILE" > "$MERGED" || true
printf 'SPRING_DATASOURCE_PASSWORD=%s\n' "$DB_PASS" >> "$MERGED"

kubectl -n "$NS" create secret generic "$SECRET" \
  --from-env-file="$MERGED" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Secret $SECRET updated in $NS"
