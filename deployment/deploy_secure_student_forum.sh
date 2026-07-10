#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/secure_student_forum"
APP_USER="forumapp"
APP_GROUP="forumapp"
SERVICE_NAME="secure-student-forum"

GUNICORN_SOCKET="/run/secure-student-forum/forum.sock"
EXPECTED_SOCKET_OWNER="forumapp"
EXPECTED_SOCKET_GROUP="www-data"
EXPECTED_SOCKET_MODE="770"

TLS_CERT="/etc/nginx/ssl/secure-student-forum.crt"
TLS_PRIVATE_KEY="/etc/nginx/ssl/secure-student-forum.key"

EXPECTED_SHA="${1:-}"

DEPLOY_HOME="${DEPLOY_HOME:-$HOME}"
DEPLOY_SSH_KEY="${DEPLOY_SSH_KEY:-${DEPLOY_HOME}/.ssh/id_ed25519}"
GIT_KNOWN_HOSTS="${GIT_KNOWN_HOSTS:-${DEPLOY_HOME}/.ssh/known_hosts}"

export GIT_SSH_COMMAND="ssh -i ${DEPLOY_SSH_KEY} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=${GIT_KNOWN_HOSTS}"

fail() {
    echo "ERROR: $1" >&2
    exit 1
}

if [[ "$#" -ne 1 ]]; then
    fail "Exactly one commit SHA must be supplied."
fi

if [[ -z "$EXPECTED_SHA" ]]; then
    fail "A commit SHA must be supplied."
fi

if [[ ! "$EXPECTED_SHA" =~ ^[0-9a-fA-F]{40}$ ]]; then
    fail "Invalid commit SHA format."
fi

echo "=============================================="
echo "Secure Student Forum deployment started"
echo "Expected commit: $EXPECTED_SHA"
echo "=============================================="

test -d "$APP_DIR" ||
    fail "Application directory does not exist."

test -d "$APP_DIR/.git" ||
    fail "Application Git repository is missing."

test -x "$APP_DIR/.venv/bin/python" ||
    fail "Application virtual environment is missing."

test -f "$APP_DIR/.env" ||
    fail ".env file is missing."

test -f "$GIT_KNOWN_HOSTS" ||
    fail "Git known_hosts file is missing."

test -f "$DEPLOY_SSH_KEY" ||
    fail "Git deployment SSH key is missing."

echo "Step 1: Fetch exact validated commit from GitHub"

git \
    -c safe.directory="$APP_DIR" \
    -C "$APP_DIR" \
    fetch origin "$EXPECTED_SHA"

if ! git \
    -c safe.directory="$APP_DIR" \
    -C "$APP_DIR" \
    cat-file -e "${EXPECTED_SHA}^{commit}"; then
    fail "Validated commit SHA was not found in repository."
fi

git \
    -c safe.directory="$APP_DIR" \
    -C "$APP_DIR" \
    reset --hard "$EXPECTED_SHA"

DEPLOYED_SHA="$(
    git \
        -c safe.directory="$APP_DIR" \
        -C "$APP_DIR" \
        rev-parse HEAD
)"

if [[ "$DEPLOYED_SHA" != "$EXPECTED_SHA" ]]; then
    fail "Deployment SHA mismatch. Expected $EXPECTED_SHA but got $DEPLOYED_SHA."
fi

echo "Step 2: Restore secure ownership and permissions"

# Application source and virtual environment remain root-owned.
# The least-privilege forumapp account receives write access only
# to application runtime-data directories.
chown -R root:root "$APP_DIR"
chmod 0755 "$APP_DIR"

install -d \
    -o "$APP_USER" \
    -g "$APP_GROUP" \
    -m 0750 \
    "$APP_DIR/instance" \
    "$APP_DIR/logs" \
    "$APP_DIR/backups"

chown -R "$APP_USER:$APP_GROUP" \
    "$APP_DIR/instance" \
    "$APP_DIR/logs" \
    "$APP_DIR/backups"

chown "$APP_USER:$APP_GROUP" "$APP_DIR/.env"
chmod 600 "$APP_DIR/.env"

echo "Step 3: Check environment-file security"

ENV_OWNER="$(stat -c '%U:%G' "$APP_DIR/.env")"
ENV_MODE="$(stat -c '%a' "$APP_DIR/.env")"

[[ "$ENV_OWNER" == "$APP_USER:$APP_GROUP" ]] ||
    fail ".env owner is $ENV_OWNER, not $APP_USER:$APP_GROUP."

[[ "$ENV_MODE" == "600" ]] ||
    fail ".env mode is $ENV_MODE, not 600."

echo "Environment-file security checks passed."

echo "Step 4: Install production dependencies"

"$APP_DIR/.venv/bin/python" -m pip install \
    --disable-pip-version-check \
    -r "$APP_DIR/requirements.txt"

echo "Step 5: Verify TLS certificate and private key"

test -f "$TLS_CERT" ||
    fail "TLS certificate is missing: $TLS_CERT"

test -f "$TLS_PRIVATE_KEY" ||
    fail "TLS private key is missing: $TLS_PRIVATE_KEY"

KEY_OWNER="$(stat -c '%U:%G' "$TLS_PRIVATE_KEY")"
KEY_MODE="$(stat -c '%a' "$TLS_PRIVATE_KEY")"

[[ "$KEY_OWNER" == "root:root" ]] ||
    fail "TLS private key owner is $KEY_OWNER, not root:root."

[[ "$KEY_MODE" == "600" ]] ||
    fail "TLS private key mode is $KEY_MODE, not 600."

openssl x509 \
    -checkend 86400 \
    -noout \
    -in "$TLS_CERT" ||
    fail "TLS certificate is invalid, expired, or expires within 24 hours."

openssl pkey \
    -in "$TLS_PRIVATE_KEY" \
    -noout \
    -check > /dev/null 2>&1 ||
    fail "TLS private key validation failed."

CERT_PUBLIC_KEY="$(
    openssl x509 \
        -in "$TLS_CERT" \
        -pubkey \
        -noout |
        openssl pkey \
            -pubin \
            -outform DER 2>/dev/null |
        sha256sum |
        awk '{print $1}'
)"

PRIVATE_PUBLIC_KEY="$(
    openssl pkey \
        -in "$TLS_PRIVATE_KEY" \
        -pubout \
        -outform DER 2>/dev/null |
        sha256sum |
        awk '{print $1}'
)"

[[ "$CERT_PUBLIC_KEY" == "$PRIVATE_PUBLIC_KEY" ]] ||
    fail "TLS certificate and private key do not match."

echo "TLS certificate and private-key checks passed."

echo "Step 6: Validate Nginx configuration"

nginx -t

echo "Step 7: Restart application services"

systemctl restart "$SERVICE_NAME"
systemctl reload nginx

echo "Step 8: Confirm services are active"

systemctl is-active --quiet "$SERVICE_NAME" ||
    fail "Gunicorn service is not active."

systemctl is-active --quiet nginx ||
    fail "Nginx service is not active."

echo "Step 9: Check Gunicorn Unix socket"

for i in {1..10}; do
    if [[ -S "$GUNICORN_SOCKET" ]]; then
        echo "Gunicorn Unix socket is available: $GUNICORN_SOCKET"
        break
    fi

    echo "Waiting for Gunicorn Unix socket... attempt $i"
    sleep 3

    if [[ "$i" -eq 10 ]]; then
        systemctl status "$SERVICE_NAME" --no-pager || true
        journalctl -u "$SERVICE_NAME" -n 50 --no-pager || true
        fail "Gunicorn Unix socket was not created."
    fi
done

if ss -ltnH |
    awk '{print $4}' |
    grep -Eq '(^|:)8000$'; then
    fail "Unexpected TCP listener detected on port 8000."
fi

echo "No Gunicorn TCP listener is exposed on port 8000."

echo "Step 10: Verify Gunicorn socket ownership and permissions"

SOCKET_OWNER="$(stat -c '%U' "$GUNICORN_SOCKET")"
SOCKET_GROUP="$(stat -c '%G' "$GUNICORN_SOCKET")"
SOCKET_MODE="$(stat -c '%a' "$GUNICORN_SOCKET")"

[[ "$SOCKET_OWNER" == "$EXPECTED_SOCKET_OWNER" ]] ||
    fail "Gunicorn socket owner is $SOCKET_OWNER, not $EXPECTED_SOCKET_OWNER."

[[ "$SOCKET_GROUP" == "$EXPECTED_SOCKET_GROUP" ]] ||
    fail "Gunicorn socket group is $SOCKET_GROUP, not $EXPECTED_SOCKET_GROUP."

[[ "$SOCKET_MODE" == "$EXPECTED_SOCKET_MODE" ]] ||
    fail "Gunicorn socket mode is $SOCKET_MODE, not $EXPECTED_SOCKET_MODE."

echo "Gunicorn socket ownership and permissions check passed."
echo "Socket owner: $SOCKET_OWNER"
echo "Socket group: $SOCKET_GROUP"
echo "Socket mode: $SOCKET_MODE"

echo "Step 11: Check internal Gunicorn response through Unix socket"

for i in {1..10}; do
    if curl \
        --unix-socket "$GUNICORN_SOCKET" \
        -fsS \
        http://localhost/ > /dev/null; then
        echo "Gunicorn Unix-socket response check passed."
        break
    fi

    echo "Waiting for Gunicorn response... attempt $i"
    sleep 3

    if [[ "$i" -eq 10 ]]; then
        systemctl status "$SERVICE_NAME" --no-pager || true
        journalctl -u "$SERVICE_NAME" -n 50 --no-pager || true
        fail "Gunicorn Unix-socket response check failed."
    fi
done

echo "Step 12: Check HTTPS reverse-proxy response"

curl -kfsS https://127.0.0.1/ > /dev/null ||
    fail "HTTPS reverse-proxy response check failed."

echo "Step 13: Check HTTP redirects to HTTPS"

HTTP_STATUS="$(
    curl \
        -s \
        -o /dev/null \
        -w '%{http_code}' \
        http://127.0.0.1/
)"

if [[ "$HTTP_STATUS" != "301" &&
      "$HTTP_STATUS" != "308" ]]; then
    fail "HTTP did not redirect to HTTPS. Received status: $HTTP_STATUS"
fi

echo "HTTP-to-HTTPS redirect check passed with status $HTTP_STATUS."

echo "Step 14: Check required security headers"

HEADERS="$(curl -k -sSI https://127.0.0.1/)"

echo "$HEADERS" |
    grep -qi '^X-Frame-Options:[[:space:]]*DENY' ||
    fail "Missing X-Frame-Options: DENY."

echo "$HEADERS" |
    grep -qi '^X-Content-Type-Options:[[:space:]]*nosniff' ||
    fail "Missing X-Content-Type-Options: nosniff."

echo "$HEADERS" |
    grep -qi '^Referrer-Policy:[[:space:]]*strict-origin-when-cross-origin' ||
    fail "Missing required Referrer-Policy."

echo "$HEADERS" |
    grep -qi '^Content-Security-Policy:' ||
    fail "Missing Content-Security-Policy."

echo "$HEADERS" |
    grep -qi '^Permissions-Policy:' ||
    fail "Missing Permissions-Policy."

echo "$HEADERS" |
    grep -qi '^Strict-Transport-Security:.*max-age=' ||
    fail "Missing Strict-Transport-Security header."

echo "Required security-header checks passed."

echo "Step 15: Confirm UFW is active"

ufw status |
    grep -q '^Status: active' ||
    fail "UFW is not active."

echo "=============================================="
echo "Deployment completed successfully"
echo "Deployed commit: $DEPLOYED_SHA"
echo "Gunicorn socket: $GUNICORN_SOCKET"
echo "Socket owner: $SOCKET_OWNER"
echo "Socket group: $SOCKET_GROUP"
echo "Socket mode: $SOCKET_MODE"
echo "=============================================="