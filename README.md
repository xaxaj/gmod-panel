# Panel GMod

Panel web léger pour gérer un serveur dédié **Garry's Mod** sur un VPS (console live, config, fichiers, joueurs, backups, ressources).

Inspiré des panels type Pterodactyl/Pelican, mais **focalisé GMod** et simple à installer.

## Fonctionnalités

- Multi-serveurs sous `/home/steam/servers/<id>`
- Start / stop / restart / kill par serveur
- Console live (WebSocket) + commandes RCON
- Configuration serveur (hostname, map, Workshop, GSLT, FastDL…)
- Explorateur de fichiers (upload, édition, archives)
- Joueurs en ligne + grades
- Backups, ressources CPU/RAM/disque, activité
- **Comptes panel** : rôles `admin` / `user` + assignation user ↔ serveur

## Prérequis

- Debian / Ubuntu (root)
- Python 3.11+
- Un serveur GMod déjà installé (SteamCMD) — par défaut : `/home/steam/servers/main`
- Service systemd `gmod` / `gmod-<id>` pour le DS (optionnel mais recommandé)

## Installation rapide

```bash
git clone https://github.com/xaxaj/gmod-panel.git /opt/gmod-panel
cd /opt/gmod-panel
sudo bash install.sh
```

Le script :
- crée l’utilisateur système **steam**
- installe le venv + service `gmod-panel`
- démarre avec **aucun serveur** (tu en crées un dans Admin → Server)
- affiche le mot de passe **admin** une fois

Ouvre `http://IP:8080` → login → Admin → Server → Ajouter.

### Réinstallation propre

```bash
systemctl stop gmod-panel || true
rm -rf /opt/gmod-panel
git clone https://github.com/xaxaj/gmod-panel.git /opt/gmod-panel
cd /opt/gmod-panel && sudo bash install.sh
```

### Variables `.env`

| Variable | Rôle |
|----------|------|
| `PANEL_PASSWORD` | Bootstrap admin si `users.json` absent |
| `PANEL_PORT` | Port HTTP (défaut `8080`) |
| `SESSION_SECRET` | Secret cookies de session |
| `GMOD_DIR` | Racine du serveur GMod |
| `RCON_HOST` / `RCON_PORT` | Accès RCON |

## Côté admin

Connecté en **admin** :

1. Onglet **Admin** → créer des comptes (`admin` ou `user`)
2. Réinitialiser / supprimer des utilisateurs
3. **Serveurs GMod** → ajouter plusieurs instances (dossier + port + unité systemd)
4. Chaque compte change son propre mot de passe dans **Mot de passe**

Le sélecteur **Serveur** en haut du panel change l’instance active (console, config, fichiers, backups…).

Les utilisateurs `user` ont accès au panel serveur ; seuls les `admin` gèrent les comptes et les instances.

## Mise à jour

```bash
cd /opt/gmod-panel
git pull
./venv/bin/pip install -r requirements.txt
sudo systemctl restart gmod-panel
```

## Sécurité

- Ne commit **jamais** `.env`, `users.json`, `server-config.json`
- Expose le panel derrière un reverse-proxy HTTPS (Caddy/Nginx) en prod
- Garde le RCON et le GSLT secrets

## Roadmap (pas encore inclus)

- Installateur SteamCMD GMod intégré à la création d’instance
- ACL par serveur / par onglet
- 2FA
- Nodes distants façon Pterodactyl Wings

## Licence

MIT — libre d’usage et de modification.
