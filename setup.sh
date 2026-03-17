#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${YELLOW}[INFO]${NC} $1"; }
ok() { echo -e "${GREEN}[OK]${NC} $1"; }
fail() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

trap 'fail "Setup failed at line $LINENO."' ERR

# Require root privileges
if [[ "${EUID}" -ne 0 ]]; then
  fail "Please run as root (example: curl -fsSL <raw-setup-url> | sudo bash)"
fi

APP_NAME="Integrated-Share"
REPO_URL="https://github.com/InferiorAK/Integrated-Share.git"
TARGET_ROOT="/var/www"
TARGET_DIR="${TARGET_ROOT}/${APP_NAME}"
SERVICE_NAME="integrated-share"
SYSTEMD_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# Check required binaries
for cmd in git python3 pip3 systemctl; do
  command -v "${cmd}" >/dev/null 2>&1 || fail "Missing required command: ${cmd}"
done

# Ensure service user exists
if id -u www-data >/dev/null 2>&1; then
  ok "User www-data already exists."
else
  info "Creating user www-data..."
  useradd --system --create-home --home-dir /var/www --shell /usr/sbin/nologin www-data
  ok "User www-data created."
fi

# Prepare target root
mkdir -p "${TARGET_ROOT}"
ok "${TARGET_ROOT} is ready."

# Clone or update repository
if [[ -d "${TARGET_DIR}/.git" ]]; then
  info "Updating existing repository in ${TARGET_DIR}..."
  git -C "${TARGET_DIR}" fetch --all --prune
  git -C "${TARGET_DIR}" reset --hard origin/main
  ok "Repository updated."
else
  info "Cloning repository to ${TARGET_DIR}..."
  rm -rf "${TARGET_DIR}"
  git clone "${REPO_URL}" "${TARGET_DIR}"
  ok "Repository cloned."
fi

# Ensure runtime folders
mkdir -p "${TARGET_DIR}/uploads" "${TARGET_DIR}/logs" "${TARGET_DIR}/instance"
ok "Runtime directories ensured."

# Install dependencies directly (no venv)
info "Installing Python dependencies..."
if pip3 install -r "${TARGET_DIR}/requirements.txt"; then
  ok "Dependencies installed."
elif pip3 install --break-system-packages -r "${TARGET_DIR}/requirements.txt"; then
  ok "Dependencies installed with --break-system-packages."
else
  fail "Could not install Python dependencies."
fi

# Set ownership and permissions
info "Applying ownership and permissions..."
chown -R www-data:www-data "${TARGET_DIR}"
find "${TARGET_DIR}" -type d -exec chmod 755 {} \;
find "${TARGET_DIR}" -type f -exec chmod 644 {} \;
chmod 775 "${TARGET_DIR}/uploads" "${TARGET_DIR}/logs" "${TARGET_DIR}/instance"
chmod 755 "${TARGET_DIR}/setup.sh" || true
[[ -f "${TARGET_DIR}/clean.sh" ]] && chmod 755 "${TARGET_DIR}/clean.sh" || true
ok "Permissions applied."

# Validate and install service
[[ -f "${TARGET_DIR}/integrated-share.service" ]] || fail "Missing integrated-share.service in repository."
cp "${TARGET_DIR}/integrated-share.service" "${SYSTEMD_FILE}"
ok "Service file installed."

# Reload and start service
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}" >/dev/null
systemctl restart "${SERVICE_NAME}"
ok "Service enabled and started."

# Verify service
if systemctl is-active --quiet "${SERVICE_NAME}"; then
  ok "${SERVICE_NAME} is active."
else
  fail "${SERVICE_NAME} is not active. Run: systemctl status ${SERVICE_NAME}"
fi

echo
ok "Deployment completed successfully."
echo -e "${YELLOW}Service commands:${NC}"
echo "  sudo systemctl start ${SERVICE_NAME}"
echo "  sudo systemctl stop ${SERVICE_NAME}"
echo "  sudo systemctl restart ${SERVICE_NAME}"
echo "  sudo systemctl status ${SERVICE_NAME}"
echo "  sudo systemctl disable ${SERVICE_NAME}"
