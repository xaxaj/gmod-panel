#!/usr/bin/env bash
# Installe le panel GMod sur Debian/Ubuntu (VPS).
set -euo pipefail

PANEL_DIR="${PANEL_DIR:-/opt/gmod-panel}"
GMOD_DIR="${GMOD_DIR:-/home/steam/gmod}"
PANEL_PORT="${PANEL_PORT:-8080}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Lance en root : sudo bash install.sh"
  exit 1
fi

echo "==> Dépendances système"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3 python3-venv python3-pip curl ca-certificates

echo "==> Dossier panel : $PANEL_DIR"
mkdir -p "$PANEL_DIR"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$SCRIPT_DIR" != "$PANEL_DIR" ]]; then
  rsync -a --exclude venv --exclude .env --exclude users.json --exclude __pycache__ \
    "$SCRIPT_DIR"/ "$PANEL_DIR"/
fi

cd "$PANEL_DIR"
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

if [[ ! -f .env ]]; then
  BOOT_PASS="$(openssl rand -hex 8)"
  SESSION="$(openssl rand -hex 24)"
  cat > .env <<EOF
PANEL_PASSWORD=${BOOT_PASS}
PANEL_PORT=${PANEL_PORT}
SESSION_SECRET=${SESSION}
GMOD_DIR=${GMOD_DIR}
RCON_HOST=127.0.0.1
RCON_PORT=27015
EOF
  chmod 600 .env
  echo ""
  echo "=============================================="
  echo " Compte admin créé automatiquement :"
  echo "   utilisateur : admin"
  echo "   mot de passe : ${BOOT_PASS}"
  echo " Change-le dès la 1ère connexion."
  echo "=============================================="
  echo ""
else
  echo "==> .env déjà présent — conservé"
fi

echo "==> Utilisateur système steam (requis pour les serveurs GMod)"
if ! id steam &>/dev/null; then
  useradd --system --create-home --home-dir /home/steam --shell /usr/sbin/nologin steam
  echo "    utilisateur steam créé"
else
  echo "    steam déjà présent"
fi
mkdir -p /home/steam/servers
chown -R steam:steam /home/steam 2>/dev/null || true

mkdir -p "$(dirname "$GMOD_DIR")"
# Ne crée pas le serveur GMod ici : ajoute-le via Admin → Server dans le panel.

if [[ -f systemd/gmod-panel.service ]]; then
  sed "s|/opt/gmod-panel|${PANEL_DIR}|g" systemd/gmod-panel.service \
    > /etc/systemd/system/gmod-panel.service
  systemctl daemon-reload
  systemctl enable --now gmod-panel
  echo "==> Service gmod-panel démarré"
fi

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo ""
echo "Panel : http://${IP:-TON_IP}:${PANEL_PORT}"
echo "Login : admin + mot de passe ci-dessus (ou celui de ton .env)"
echo "Done."
