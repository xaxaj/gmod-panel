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
STEAMCMD = Path("/home/steam/gmod/steamcmd/steamcmd.sh")
GMOD_DIR = Path("/home/steam/gmod")
MAX_ACTIVITY = 200
MAX_BACKUPS = 20


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


def list_backups() -> list[dict]:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    _steam_chown(BACKUP_DIR)
    items = []
    for p in sorted(BACKUP_DIR.glob("*.tar.gz"), key=lambda x: x.stat().st_mtime, reverse=True):
        st = p.stat()
        items.append({
            "name": p.name,
            "size": st.st_size,
            "mtime": int(st.st_mtime),
            "path": p.name,
        })
    return items


def create_backup(note: str = "") -> dict[str, Any]:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_note = re.sub(r"[^\w\-]+", "_", (note or "").strip())[:40].strip("_")
    name = f"gmod_{stamp}{('_' + safe_note) if safe_note else ''}.tar.gz"
    dest = BACKUP_DIR / name
    # Backup addons + cfg + darkrp data essentials (not full game binaries)
    includes = [
        "garrysmod/addons",
        "garrysmod/cfg",
        "garrysmod/data",
        "garrysmod/lua",
        "garrysmod/gamemodes",
        "garrysmod/settings",
        "start.sh",
    ]
    existing = [i for i in includes if (GMOD_DIR / i).exists()]
    if not existing:
        raise RuntimeError("rien à sauvegarder")
    cmd = ["tar", "-czf", str(dest), "-C", str(GMOD_DIR), *existing]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if proc.returncode != 0 or not dest.exists():
        dest.unlink(missing_ok=True)
        raise RuntimeError((proc.stderr or proc.stdout or "échec tar")[-500:])
    _steam_chown(dest)
    # prune old
    all_b = sorted(BACKUP_DIR.glob("*.tar.gz"), key=lambda x: x.stat().st_mtime, reverse=True)
    for old in all_b[MAX_BACKUPS:]:
        old.unlink(missing_ok=True)
    log_activity("backup.create", name, True)
    return {"name": name, "size": dest.stat().st_size}


def delete_backup(name: str) -> None:
    name = Path(name).name
    if not name.endswith(".tar.gz") or ".." in name:
        raise ValueError("nom invalide")
    path = BACKUP_DIR / name
    if not path.exists():
        raise FileNotFoundError("backup introuvable")
    path.unlink()
    log_activity("backup.delete", name, True)


def restore_backup(name: str) -> None:
    name = Path(name).name
    if not name.endswith(".tar.gz") or ".." in name:
        raise ValueError("nom invalide")
    path = BACKUP_DIR / name
    if not path.exists():
        raise FileNotFoundError("backup introuvable")
    proc = subprocess.run(
        ["tar", "-xzf", str(path), "-C", str(GMOD_DIR)],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "échec restore")[-500:])
    _steam_chown(GMOD_DIR / "garrysmod")
    log_activity("backup.restore", name, True)


def steamcmd_update(validate: bool = True) -> str:
    if not STEAMCMD.exists():
        raise FileNotFoundError(f"steamcmd introuvable: {STEAMCMD}")
    cmd = [
        str(STEAMCMD),
        "+force_install_dir",
        str(GMOD_DIR),
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
        cwd=str(STEAMCMD.parent),
        capture_output=True,
        text=True,
        timeout=3600,
        user="steam",
    )
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    ok = proc.returncode == 0
    log_activity("steamcmd.update", f"code={proc.returncode}", ok)
    if not ok:
        raise RuntimeError(out[-2000:] or f"steamcmd exit {proc.returncode}")
    return out[-3000:]


def kill_gmod() -> tuple[int, str]:
    # force kill srcds then stop unit
    subprocess.run(["pkill", "-9", "-f", "srcds_"], capture_output=True, text=True)
    proc = subprocess.run(
        ["systemctl", "kill", "-s", "SIGKILL", "gmod"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    subprocess.run(["systemctl", "stop", "gmod"], capture_output=True, text=True, timeout=30)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    log_activity("power.kill", out[:200], True)
    return proc.returncode, out
