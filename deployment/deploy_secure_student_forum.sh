#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/secure_student_forum"
APP_USER="forumapp"
APP_GROUP="forumapp"
SERVICE_NAME="secure-student-forum"
EXPECTED_SHA="${1:-}"

DEPLOY_HOME="${DEPLOY_HOME:-$HOME}"
DEPLOY_SSH_KEY="${DEPLOY_SSH_KEY:-${DEPLOY_HOME}/.ssh/id_ed25519}"
GIT_KNOWN_HOSTS="${GIT_KNOWN_HOSTS:-${DEPLOY_HOME}/.ssh/known_hosts}"

export GIT_SSH_COMMAND="ssh -i ${DEPLOY_SSH_KEY} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=${GIT_KNOWN_HOSTS}"

fail() {
    echo "ERROR: $1"
    exit 1
}

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

test -d "$APP_DIR" || fail "Application directory does not exist."
test -f "$APP_DIR/.env" || fail ".env file is missing."

echo "Step 1: Fetch exact validated commit from GitHub"

git -c safe.directory="$APP_DIR" -C "$APP_DIR" fetch origin "$EXPECTED_SHA"

if ! git -c safe.directory="$APP_DIR" -C "$APP_DIR" cat-file -e "${EXPECTED_SHA}^{commit}"; then
    fail "Validated commit SHA was not found in repository."
fi

git -c safe.directory="$APP_DIR" -C "$APP_DIR" reset --hard "$EXPECTED_SHA"

DEPLOYED_SHA="$(git -c safe.directory="$APP_DIR" -C "$APP_DIR" rev-parse HEAD)"

if [[ "$DEPLOYED_SHA" != "$EXPECTED_SHA" ]]; then
    fail "Deployment SHA mismatch. Expected $EXPECTED_SHA but got $DEPLOYED_SHA."
fi

echo "Step 3: Restore secure ownership and permissions"

find "$APP_DIR" -path "$APP_DIR/.git" -prune -o -exec chown "$APP_USER:$APP_GROUP" {} +
chown -R root:root "$APP_DIR/.git"

chown "$APP_USER:$APP_GROUP" "$APP_DIR/.env"
chmod 600 "$APP_DIR/.env"

echo "Step 4: Check environment-file security"

ENV_OWNER="$(stat -c '%U:%G' "$APP_DIR/.env")"
ENV_MODE="$(stat -c '%a' "$APP_DIR/.env")"

[[ "$ENV_OWNER" == "$APP_USER:$APP_GROUP" ]] || fail ".env owner is $ENV_OWNER, not $APP_USER:$APP_GROUP."
[[ "$ENV_MODE" == "600" ]] || fail ".env mode is $ENV_MODE, not 600."

echo "Step 5: Install production dependencies"

sudo -u "$APP_USER" -H "$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"

echo "Step 6: Validate Nginx configuration"

nginx -t

echo "Step 7: Restart application services"

systemctl restart "$SERVICE_NAME"
systemctl reload nginx

echo "Step 8: Confirm services are active"

systemctl is-active --quiet "$SERVICE_NAME" || fail "Gunicorn service is not active."
systemctl is-active --quiet nginx || fail "Nginx service is not active."

echo "Step 9: Check Gunicorn listening address"

for i in {1..10}; do
    LISTENERS="$(ss -ltnp | grep ':8000' || true)"

    if echo "$LISTENERS" | grep -q '127.0.0.1:8000'; then
        echo "Gunicorn is listening on 127.0.0.1:8000."
        break
    fi

    echo "Waiting for Gunicorn listener... attempt $i"
    sleep 3

    if [[ "$i" -eq 10 ]]; then
        systemctl status "$SERVICE_NAME" --no-pager || true
        journalctl -u "$SERVICE_NAME" -n 50 --no-pager || true
        fail "Gunicorn did not start listening on 127.0.0.1:8000."
    fi
done

if echo "$LISTENERS" | grep -q '0.0.0.0:8000'; then
    fail "Gunicorn is incorrectly exposed on 0.0.0.0:8000."
fi

echo "Step 10: Check internal Gunicorn response"

for i in {1..10}; do
    if curl -fsS http://127.0.0.1:8000/ > /dev/null; then
        echo "Gunicorn internal response check passed."
        break
    fi

    echo "Waiting for Gunicorn HTTP response... attempt $i"
    sleep 3

    if [[ "$i" -eq 10 ]]; then
        systemctl status "$SERVICE_NAME" --no-pager || true
        journalctl -u "$SERVICE_NAME" -n 50 --no-pager || true
        fail "Gunicorn internal response check failed."
    fi
done	

echo "Step 11: Check HTTPS reverse proxy response"

curl -kfsS https://127.0.0.1/ > /dev/null || fail "HTTPS reverse proxy response check failed."

echo "Step 12: Check HTTP redirects to HTTPS"

HTTP_STATUS="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1/)"

if [[ "$HTTP_STATUS" != "301" && "$HTTP_STATUS" != "308" ]]; then
    fail "HTTP did not redirect to HTTPS. Received status: $HTTP_STATUS"
fi

echo "Step 13: Check required security headers"

HEADERS="$(curl -k -sI https://127.0.0.1/)"

echo "$HEADERS" | grep -qi '^X-Frame-Options: DENY' || fail "Missing X-Frame-Options: DENY."
echo "$HEADERS" | grep -qi '^X-Content-Type-Options: nosniff' || fail "Missing X-Content-Type-Options: nosniff."
echo "$HEADERS" | grep -qi '^Referrer-Policy: strict-origin-when-cross-origin' || fail "Missing required Referrer-Policy."
echo "$HEADERS" | grep -qi '^Content-Security-Policy:' || fail "Missing Content-Security-Policy."
echo "$HEADERS" | grep -qi '^Permissions-Policy:' || fail "Missing Permissions-Policy."

echo "Step 14: Confirm UFW is active"

ufw status | grep -q "Status: active" || fail "UFW is not active."

echo "=============================================="
echo "Deployment completed successfully"
echo "Deployed commit: $DEPLOYED_SHA"
echo "=============================================="
