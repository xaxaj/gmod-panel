#!/usr/bin/env python3
"""Fonctionnalités type Pelican / Pterodactyl pour le panel GMod."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

BACKUP_DIR = Path("/home/steam/gmod-backups")
ACTIVITY_FILE = Path("/opt/gmod-panel/activity.json")
STEAMCMD_DIR = Path("/home/steam/steamcmd")
STEAMCMD = STEAMCMD_DIR / "steamcmd.sh"
GMOD_DIR = Path("/home/steam/gmod")
MAX_ACTIVITY = 200
MAX_BACKUPS = 20
STEAMCMD_URL = "https://steamcdn-a.akamaihd.net/client/installer/steamcmd_linux.tar.gz"

# id serveur → {status: pending|running|ok|error, detail: str}
_install_jobs: dict[str, dict[str, str]] = {}


def get_install_job(server_id: str) -> dict[str, str]:
    return dict(_install_jobs.get(server_id) or {})


def has_gmod_bin(gmod_dir: Path) -> bool:
    gdir = Path(gmod_dir)
    return (gdir / "srcds_run_x64").exists() or (gdir / "srcds_linux").exists()


def _steam_chown(path: Path) -> None:
    try:
        import pwd

        steam = pwd.getpwnam("steam")
        os.chown(path, steam.pw_uid, steam.pw_gid)
        if path.is_dir():
            for root, dirs, files in os.walk(path):
                for name in dirs + files:
                    try:
                        os.chown(os.path.join(root, name), steam.pw_uid, steam.pw_gid)
                    except OSError:
                        pass
    except Exception:
        pass


def log_activity(action: str, detail: str = "", ok: bool = True) -> None:
    entry = {
        "ts": int(time.time()),
        "iso": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "detail": (detail or "")[:500],
        "ok": bool(ok),
    }
    rows: list[dict] = []
    if ACTIVITY_FILE.exists():
        try:
            data = json.loads(ACTIVITY_FILE.read_text(encoding="utf-8"))
            if isinstance(data, list):
                rows = data
        except Exception:
            rows = []
    rows.insert(0, entry)
    rows = rows[:MAX_ACTIVITY]
    ACTIVITY_FILE.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    try:
        ACTIVITY_FILE.chmod(0o600)
    except Exception:
        pass


def read_activity(limit: int = 50) -> list[dict]:
    if not ACTIVITY_FILE.exists():
        return []
    try:
        data = json.loads(ACTIVITY_FILE.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data[: max(1, min(limit, MAX_ACTIVITY))]
    except Exception:
        pass
    return []


def resources_snapshot() -> dict[str, Any]:
    mem = {"total": 0, "used": 0, "available": 0, "percent": 0.0}
    try:
        info: dict[str, int] = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                info[parts[0].rstrip(":")] = int(parts[1]) * 1024
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", info.get("MemFree", 0))
        used = max(0, total - avail)
        mem = {
            "total": total,
            "used": used,
            "available": avail,
            "percent": round((used / total) * 100, 1) if total else 0.0,
        }
    except Exception:
        pass

    disk = {"total": 0, "used": 0, "free": 0, "percent": 0.0, "path": str(GMOD_DIR)}
    try:
        usage = shutil.disk_usage(str(GMOD_DIR))
        disk = {
            "total": usage.total,
            "used": usage.used,
            "free": usage.free,
            "percent": round((usage.used / usage.total) * 100, 1) if usage.total else 0.0,
            "path": str(GMOD_DIR),
        }
    except Exception:
        pass

    cpu_percent = 0.0
    loadavg = [0.0, 0.0, 0.0]
    try:
        loadavg = list(os.getloadavg())
        # rough CPU% from 1-min load / nproc
        nproc = os.cpu_count() or 1
        cpu_percent = round(min(100.0, (loadavg[0] / nproc) * 100), 1)
    except Exception:
        pass

    gmod_rss = 0
    try:
        out = subprocess.check_output(
            ["ps", "-C", "srcds_linux", "-C", "srcds_linux_x64", "-o", "rss=", "--no-headers"],
            text=True,
            timeout=3,
        )
        for line in out.splitlines():
            line = line.strip()
            if line.isdigit():
                gmod_rss += int(line) * 1024
    except Exception:
        pass

    return {
        "ok": True,
        "cpu_percent": cpu_percent,
        "loadavg": loadavg,
        "memory": mem,
        "disk": disk,
        "gmod_rss": gmod_rss,
        "uptime_seconds": _uptime_seconds(),
    }


def _uptime_seconds() -> int:
    try:
        return int(float(Path("/proc/uptime").read_text().split()[0]))
    except Exception:
        return 0


def list_backups(backup_dir: Optional[Path] = None) -> list[dict]:
    bdir = Path(backup_dir) if backup_dir else BACKUP_DIR
    bdir.mkdir(parents=True, exist_ok=True)
    _steam_chown(bdir)
    items = []
    for p in sorted(bdir.glob("*.tar.gz"), key=lambda x: x.stat().st_mtime, reverse=True):
        st = p.stat()
        items.append({
            "name": p.name,
            "size": st.st_size,
            "mtime": int(st.st_mtime),
            "path": p.name,
        })
    return items


def create_backup(
    note: str = "",
    gmod_dir: Optional[Path] = None,
    backup_dir: Optional[Path] = None,
) -> dict[str, Any]:
    gdir = Path(gmod_dir) if gmod_dir else GMOD_DIR
    bdir = Path(backup_dir) if backup_dir else BACKUP_DIR
    bdir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_note = re.sub(r"[^\w\-]+", "_", (note or "").strip())[:40].strip("_")
    name = f"gmod_{stamp}{('_' + safe_note) if safe_note else ''}.tar.gz"
    dest = bdir / name
    includes = [
        "garrysmod/addons",
        "garrysmod/cfg",
        "garrysmod/data",
        "garrysmod/lua",
        "garrysmod/gamemodes",
        "garrysmod/settings",
        "start.sh",
    ]
    existing = [i for i in includes if (gdir / i).exists()]
    if not existing:
        raise RuntimeError("rien à sauvegarder")
    cmd = ["tar", "-czf", str(dest), "-C", str(gdir), *existing]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if proc.returncode != 0 or not dest.exists():
        dest.unlink(missing_ok=True)
        raise RuntimeError((proc.stderr or proc.stdout or "échec tar")[-500:])
    _steam_chown(dest)
    all_b = sorted(bdir.glob("*.tar.gz"), key=lambda x: x.stat().st_mtime, reverse=True)
    for old in all_b[MAX_BACKUPS:]:
        old.unlink(missing_ok=True)
    log_activity("backup.create", name, True)
    return {"name": name, "size": dest.stat().st_size}


def delete_backup(name: str, backup_dir: Optional[Path] = None) -> None:
    bdir = Path(backup_dir) if backup_dir else BACKUP_DIR
    name = Path(name).name
    if not name.endswith(".tar.gz") or ".." in name:
        raise ValueError("nom invalide")
    path = bdir / name
    if not path.exists():
        raise FileNotFoundError("backup introuvable")
    path.unlink()
    log_activity("backup.delete", name, True)


def restore_backup(
    name: str,
    gmod_dir: Optional[Path] = None,
    backup_dir: Optional[Path] = None,
) -> None:
    gdir = Path(gmod_dir) if gmod_dir else GMOD_DIR
    bdir = Path(backup_dir) if backup_dir else BACKUP_DIR
    name = Path(name).name
    if not name.endswith(".tar.gz") or ".." in name:
        raise ValueError("nom invalide")
    path = bdir / name
    if not path.exists():
        raise FileNotFoundError("backup introuvable")
    proc = subprocess.run(
        ["tar", "-xzf", str(path), "-C", str(gdir)],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "échec restore")[-500:])
    _steam_chown(gdir / "garrysmod")
    log_activity("backup.restore", name, True)


def ensure_steamcmd() -> Path:
    """Installe SteamCMD sous /home/steam/steamcmd si besoin."""
    import pwd

    cmd = STEAMCMD
    if cmd.exists():
        return cmd

    legacy = Path("/home/steam/gmod/steamcmd/steamcmd.sh")
    if legacy.exists():
        return legacy

    STEAMCMD_DIR.mkdir(parents=True, exist_ok=True)
    tar_path = STEAMCMD_DIR / "steamcmd_linux.tar.gz"
    try:
        subprocess.run(
            ["curl", "-fsSL", "-o", str(tar_path), STEAMCMD_URL],
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
        )
        subprocess.run(
            ["tar", "-xzf", str(tar_path), "-C", str(STEAMCMD_DIR)],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except Exception as e:
        raise RuntimeError(f"téléchargement SteamCMD échoué: {e}") from e
    finally:
        try:
            tar_path.unlink(missing_ok=True)
        except Exception:
            pass

    if not cmd.exists():
        raise FileNotFoundError(f"steamcmd toujours introuvable: {cmd}")

    try:
        pwd.getpwnam("steam")
        _steam_chown(STEAMCMD_DIR)
        subprocess.run(
            [str(cmd), "+quit"],
            cwd=str(STEAMCMD_DIR),
            capture_output=True,
            text=True,
            timeout=180,
            user="steam",
        )
        _steam_chown(STEAMCMD_DIR)
    except Exception:
        pass
    return cmd


def steamcmd_update(
    validate: bool = True,
    gmod_dir: Optional[Path] = None,
    steamcmd: Optional[Path] = None,
) -> str:
    gdir = Path(gmod_dir) if gmod_dir else GMOD_DIR
    gdir.mkdir(parents=True, exist_ok=True)
    _steam_chown(gdir)
    cmd_bin = Path(steamcmd) if steamcmd else ensure_steamcmd()
    if not cmd_bin.exists():
        raise FileNotFoundError(f"steamcmd introuvable: {cmd_bin}")
    cmd = [
        str(cmd_bin),
        "+force_install_dir",
        str(gdir),
        "+login",
        "anonymous",
        "+app_update",
        "4020",
        "-beta",
        "x86-64",
    ]
    if validate:
        cmd.append("validate")
    cmd.append("+quit")
    proc = subprocess.run(
        cmd,
        cwd=str(cmd_bin.parent),
        capture_output=True,
        text=True,
        timeout=7200,
        user="steam",
    )
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    ok = proc.returncode == 0 and has_gmod_bin(gdir)
    log_activity("steamcmd.update", f"code={proc.returncode} dir={gdir}", ok)
    if not ok:
        raise RuntimeError(
            (out[-1800:] if out else "")
            or f"steamcmd exit {proc.returncode} — srcds toujours absent dans {gdir}"
        )
    _steam_chown(gdir)
    return out[-3000:]


def start_gmod_install(server_id: str, gmod_dir: Path, installer: Callable[[Path], str]) -> dict[str, str]:
    """Lance l'install GMod en arrière-plan (clone ou SteamCMD)."""
    sid = str(server_id)
    cur = _install_jobs.get(sid) or {}
    if cur.get("status") == "running":
        return dict(cur)
    if has_gmod_bin(gmod_dir):
        _install_jobs[sid] = {"status": "ok", "detail": "déjà installé"}
        return dict(_install_jobs[sid])

    import threading

    _install_jobs[sid] = {"status": "running", "detail": "Téléchargement GMod (SteamCMD)…"}

    def _run() -> None:
        try:
            ensure_steamcmd()
            how = installer(Path(gmod_dir))
            if not has_gmod_bin(gmod_dir):
                raise RuntimeError("install terminée mais srcds_run_x64 introuvable")
            _install_jobs[sid] = {"status": "ok", "detail": how}
            log_activity("server.install", f"{sid}: {how}", True)
        except Exception as e:
            _install_jobs[sid] = {"status": "error", "detail": str(e)[-500:]}
            log_activity("server.install", f"{sid}: {e}", False)

    threading.Thread(target=_run, name=f"gmod-install-{sid}", daemon=True).start()
    return dict(_install_jobs[sid])


def kill_gmod(unit: str = "gmod") -> tuple[int, str]:
    proc = subprocess.run(
        ["systemctl", "kill", "-s", "SIGKILL", unit],
        capture_output=True,
        text=True,
        timeout=30,
    )
    subprocess.run(["systemctl", "stop", unit], capture_output=True, text=True, timeout=30)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    log_activity("power.kill", f"{unit} {out[:180]}", True)
    return proc.returncode, out
