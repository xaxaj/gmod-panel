#!/usr/bin/env python3
"""Registre multi-serveurs pour le panel GMod."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

BASE = Path(__file__).resolve().parent
SERVERS_FILE = BASE / "servers.json"
DATA_ROOT = BASE / "data"
LEGACY_CONFIG = BASE / "server-config.json"
SERVERS_ROOT = Path("/home/steam/servers")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,31}$")

_current: ContextVar[Optional["ServerCtx"]] = ContextVar("server_ctx", default=None)


@dataclass
class ServerCtx:
    id: str
    name: str
    gmod_dir: Path
    unit: str
    owner: str = ""

    @property
    def config_file(self) -> Path:
        return DATA_ROOT / self.id / "server-config.json"

    @property
    def start_sh(self) -> Path:
        return self.gmod_dir / "start.sh"

    @property
    def server_cfg(self) -> Path:
        return self.gmod_dir / "garrysmod" / "cfg" / "server.cfg"

    @property
    def rcon_file(self) -> Path:
        return self.gmod_dir / "rcon_password.txt"

    @property
    def players_json(self) -> Path:
        return self.gmod_dir / "garrysmod" / "data" / "cloudix_panel" / "players.json"

    @property
    def ranks_json(self) -> Path:
        return self.gmod_dir / "garrysmod" / "data" / "cloudix_panel" / "ranks.json"

    @property
    def files_root(self) -> Path:
        return self.gmod_dir

    @property
    def backup_dir(self) -> Path:
        # Compat ancien mono-serveur
        if self.id == "main" and str(self.gmod_dir) in ("/home/steam/gmod",):
            return Path("/home/steam/gmod-backups")
        return SERVERS_ROOT / self.id / "backups"

    def to_public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "gmod_dir": str(self.gmod_dir),
            "unit": self.unit,
            "owner": self.owner or "",
        }


def _default_gmod() -> Path:
    env = os.environ.get("GMOD_DIR") or ""
    if env:
        return Path(env)
    # .env file fallback read lightly
    env_file = BASE / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("GMOD_DIR="):
                return Path(line.split("=", 1)[1].strip() or "/home/steam/gmod")
    return Path("/home/steam/gmod")


def load_registry() -> list[dict[str, Any]]:
    if not SERVERS_FILE.exists():
        return []
    try:
        data = json.loads(SERVERS_FILE.read_text(encoding="utf-8"))
        rows = data.get("servers") if isinstance(data, dict) else data
        return list(rows or [])
    except Exception:
        return []


def save_registry(rows: list[dict[str, Any]]) -> None:
    SERVERS_FILE.write_text(
        json.dumps({"servers": rows}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    try:
        SERVERS_FILE.chmod(0o600)
    except Exception:
        pass


def row_to_ctx(row: dict[str, Any]) -> ServerCtx:
    return ServerCtx(
        id=str(row["id"]),
        name=str(row.get("name") or row["id"]),
        gmod_dir=Path(str(row.get("gmod_dir") or _default_gmod())),
        unit=str(row.get("unit") or "gmod"),
        owner=str(row.get("owner") or "").strip(),
    )


def user_can_access(ctx: ServerCtx, username: str, role: str) -> bool:
    """admin = tout · sinon uniquement les serveurs assignés (owner vide = libre)."""
    if role == "admin":
        return True
    owner = (ctx.owner or "").strip().lower()
    if not owner:
        return True
    return owner == (username or "").strip().lower()


def list_servers_for(username: str, role: str) -> list[ServerCtx]:
    return [s for s in list_servers() if user_can_access(s, username, role)]


def list_servers() -> list[ServerCtx]:
    ensure_migrated()
    return [row_to_ctx(r) for r in load_registry()]


def get_server_by_id(server_id: Optional[str]) -> ServerCtx:
    servers = list_servers()
    if not servers:
        raise RuntimeError("aucun serveur configuré")
    if not server_id:
        return servers[0]
    for s in servers:
        if s.id == server_id:
            return s
    raise KeyError(f"serveur inconnu: {server_id}")


def ensure_migrated() -> None:
    """Initialise servers.json. Ne crée un serveur auto QUE si une install GMod existe déjà."""
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    rows = load_registry()
    if rows:
        for r in rows:
            (DATA_ROOT / r["id"]).mkdir(parents=True, exist_ok=True)
            ctx = row_to_ctx(r)
            if not ctx.config_file.exists() and LEGACY_CONFIG.exists() and r["id"] == "main":
                shutil.copy2(LEGACY_CONFIG, ctx.config_file)
        return

    # Fresh install : registre vide — pas de serveur fantôme
    gmod = _default_gmod()
    has_game = (gmod / "srcds_run_x64").exists() or (gmod / "srcds_linux").exists()
    if not has_game:
        if not SERVERS_FILE.exists():
            save_registry([])
        return

    row = {
        "id": "main",
        "name": "Serveur principal",
        "gmod_dir": str(gmod),
        "unit": "gmod",
        "owner": "",
        "created_at": int(time.time()),
    }
    (DATA_ROOT / "main").mkdir(parents=True, exist_ok=True)
    cfg_path = DATA_ROOT / "main" / "server-config.json"
    if LEGACY_CONFIG.exists() and not cfg_path.exists():
        shutil.copy2(LEGACY_CONFIG, cfg_path)
    save_registry([row])


def set_current(ctx: Optional[ServerCtx]):
    return _current.set(ctx)


def reset_current(token) -> None:
    _current.reset(token)


def current() -> ServerCtx:
    ctx = _current.get()
    if ctx is None:
        # fallback default (boot / scripts)
        return get_server_by_id(None)
    return ctx


def ensure_steam_user() -> None:
    """Crée l'utilisateur système steam si absent (requis par les unités systemd)."""
    import pwd

    try:
        pwd.getpwnam("steam")
    except KeyError:
        proc = subprocess.run(
            [
                "useradd",
                "--system",
                "--create-home",
                "--home-dir",
                "/home/steam",
                "--shell",
                "/usr/sbin/nologin",
                "steam",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        try:
            pwd.getpwnam("steam")
        except KeyError as e:
            detail = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(
                f"utilisateur système 'steam' introuvable et impossible à créer: {detail or proc.returncode}"
            ) from e

    steam = pwd.getpwnam("steam")
    for path in (Path("/home/steam"), SERVERS_ROOT):
        path.mkdir(parents=True, exist_ok=True)
        try:
            os.chown(path, steam.pw_uid, steam.pw_gid)
        except OSError:
            pass


def write_systemd_unit(ctx: ServerCtx) -> Path:
    ensure_steam_user()
    unit_path = Path(f"/etc/systemd/system/{ctx.unit}.service")
    body = f"""[Unit]
Description=Garry's Mod DS ({ctx.name})
After=network.target

[Service]
Type=simple
User=steam
Group=steam
WorkingDirectory={ctx.gmod_dir}
ExecStart={ctx.start_sh}
Restart=on-failure
RestartSec=8
StartLimitIntervalSec=120
StartLimitBurst=3
LimitNOFILE=100000

[Install]
WantedBy=multi-user.target
"""
    unit_path.write_text(body, encoding="utf-8")
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True, text=True, timeout=30)
    subprocess.run(["systemctl", "enable", ctx.unit], capture_output=True, text=True, timeout=30)
    return unit_path


def clone_game_files(src: Path, dest: Path) -> None:
    """Copie une install GMod existante (plus fiable que SteamCMD à froid)."""
    src = Path(src)
    dest = Path(dest)
    if not (src / "srcds_run_x64").exists() and not (src / "srcds_linux").exists():
        raise FileNotFoundError(f"source invalide: {src}")
    dest.mkdir(parents=True, exist_ok=True)
    excludes = [
        "--exclude=backups",
        "--exclude=start.sh",
        "--exclude=rcon_password.txt",
        "--exclude=garrysmod/cfg/server.cfg",
        "--exclude=garrysmod/data/cloudix_panel",
    ]
    if shutil.which("rsync"):
        cmd = ["rsync", "-a", *excludes, f"{src}/", f"{dest}/"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout or "rsync failed")[-500:])
    else:
        # tar pipe fallback
        excl_args = [
            "--exclude=backups",
            "--exclude=start.sh",
            "--exclude=rcon_password.txt",
            "--exclude=garrysmod/cfg/server.cfg",
            "--exclude=garrysmod/data/cloudix_panel",
        ]
        cmd = f"tar -C {src} {' '.join(excl_args)} -cf - . | tar -C {dest} -xf -"
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=3600)
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout or "tar failed")[-500:])
    try:
        import pwd

        steam = pwd.getpwnam("steam")
        for root, dirs, files in os.walk(dest):
            try:
                os.chown(root, steam.pw_uid, steam.pw_gid)
            except OSError:
                pass
            for name in dirs + files:
                try:
                    os.chown(os.path.join(root, name), steam.pw_uid, steam.pw_gid)
                except OSError:
                    pass
    except Exception:
        pass


def install_gmod(dest: Path, *, prefer_clone_from: Optional[Path] = None) -> str:
    """Installe GMod dans dest : clone depuis un serveur existant, sinon SteamCMD."""
    import pelican_ext as pelican

    dest = Path(dest)
    if pelican.has_gmod_bin(dest):
        return "déjà installé"
    # Cherche un template
    template = prefer_clone_from
    if template is None:
        for row in load_registry():
            p = Path(row.get("gmod_dir") or "")
            if p.resolve() == dest.resolve():
                continue
            if pelican.has_gmod_bin(p):
                template = p
                break
    if template is not None:
        clone_game_files(template, dest)
        return f"cloné depuis {template}"
    pelican.ensure_steamcmd()
    pelican.steamcmd_update(validate=True, gmod_dir=dest)
    return "installé via SteamCMD"


def create_server(
    *,
    server_id: str,
    name: str,
    gmod_dir: str = "",
    unit: str = "",
    port: int = 27015,
    owner: str = "",
) -> ServerCtx:
    ensure_migrated()
    sid = (server_id or "").strip().lower()
    if not ID_RE.match(sid):
        raise ValueError("id invalide (2–32, a-z 0-9 _ -)")
    if any(r["id"] == sid for r in load_registry()):
        raise ValueError("id déjà utilisé")
    name = (name or sid).strip()[:64] or sid
    owner = (owner or "").strip()
    # Convention fixe : /home/steam/servers/<id>
    ensure_steam_user()
    SERVERS_ROOT.mkdir(parents=True, exist_ok=True)
    gdir = SERVERS_ROOT / sid
    unit = (unit or f"gmod-{sid}").strip()
    if not re.match(r"^[a-zA-Z0-9@_.\\-]+$", unit):
        raise ValueError("nom d'unité systemd invalide")
    if any(r.get("unit") == unit for r in load_registry()):
        raise ValueError("unité systemd déjà utilisée")
    if any(Path(r.get("gmod_dir", "")).resolve() == gdir.resolve() for r in load_registry()):
        raise ValueError("ce dossier gmod est déjà lié")

    gdir.mkdir(parents=True, exist_ok=True)
    (gdir / "garrysmod" / "cfg").mkdir(parents=True, exist_ok=True)
    (DATA_ROOT / sid).mkdir(parents=True, exist_ok=True)
    backup = gdir / "backups"
    backup.mkdir(parents=True, exist_ok=True)

    try:
        import pwd

        steam = pwd.getpwnam("steam")
        for p in (SERVERS_ROOT, gdir, backup, gdir / "garrysmod"):
            try:
                os.chown(p, steam.pw_uid, steam.pw_gid)
            except OSError:
                pass
    except Exception:
        pass

    row = {
        "id": sid,
        "name": name,
        "gmod_dir": str(gdir),
        "unit": unit,
        "owner": owner,
        "created_at": int(time.time()),
    }
    rows = load_registry()
    rows.append(row)
    save_registry(rows)
    ctx = row_to_ctx(row)
    write_systemd_unit(ctx)
    return ctx


def rename_server(server_id: str, name: str) -> ServerCtx:
    name = (name or "").strip()[:64]
    if len(name) < 2:
        raise ValueError("nom trop court")
    rows = load_registry()
    target = None
    for r in rows:
        if r["id"] == server_id:
            r["name"] = name
            target = r
            break
    if not target:
        raise KeyError("serveur introuvable")
    save_registry(rows)
    return row_to_ctx(target)


def update_server(server_id: str, *, name: Optional[str] = None, owner: Optional[str] = None) -> ServerCtx:
    rows = load_registry()
    target = None
    for r in rows:
        if r["id"] == server_id:
            if name is not None:
                n = str(name).strip()[:64]
                if len(n) < 2:
                    raise ValueError("nom trop court")
                r["name"] = n
            if owner is not None:
                r["owner"] = str(owner).strip()
            target = r
            break
    if not target:
        raise KeyError("serveur introuvable")
    save_registry(rows)
    return row_to_ctx(target)


def _safe_rmtree(path: Path) -> None:
    """Supprime un dossier seulement s'il est sous un racine autorisée."""
    try:
        resolved = path.resolve()
    except Exception:
        return
    if not resolved.exists():
        return
    allowed = [
        SERVERS_ROOT.resolve(),
        DATA_ROOT.resolve(),
        Path("/home/steam/gmod").resolve(),
        Path("/home/steam/gmod-backups").resolve(),
    ]
    for root in allowed:
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        # ne jamais supprimer la racine servers/ elle-même
        if resolved == root and root in (SERVERS_ROOT.resolve(), DATA_ROOT.resolve()):
            return
        shutil.rmtree(resolved, ignore_errors=True)
        return


def delete_server(server_id: str, *, remove_files: bool = True) -> None:
    rows = load_registry()
    target = next((r for r in rows if r["id"] == server_id), None)
    if not target:
        raise KeyError("serveur introuvable")
    ctx = row_to_ctx(target)

    # Arrêt forcé + désactivation
    ensure_steam_user()
    subprocess.run(
        ["systemctl", "kill", "-s", "SIGKILL", ctx.unit],
        capture_output=True, text=True, timeout=30,
    )
    subprocess.run(["systemctl", "stop", ctx.unit], capture_output=True, text=True, timeout=60)
    subprocess.run(["systemctl", "disable", ctx.unit], capture_output=True, text=True, timeout=30)
    unit_path = Path(f"/etc/systemd/system/{ctx.unit}.service")
    if unit_path.exists() and ctx.unit.startswith("gmod"):
        unit_path.unlink(missing_ok=True)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, text=True, timeout=30)
        subprocess.run(["systemctl", "reset-failed", ctx.unit], capture_output=True, text=True, timeout=15)

    rows = [r for r in rows if r["id"] != server_id]
    save_registry(rows)

    if remove_files:
        # install jeu + backups + data panel
        gmod = Path(ctx.gmod_dir)
        _safe_rmtree(gmod)
        # si l'install est /home/steam/servers/<id>/… et qu'il reste le dossier id
        server_home = SERVERS_ROOT / server_id
        if server_home.exists():
            _safe_rmtree(server_home)
        # backups legacy éventuels
        if ctx.id == "main":
            _safe_rmtree(Path("/home/steam/gmod-backups"))
        _safe_rmtree(DATA_ROOT / server_id)
