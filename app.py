#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, File, Form, Request, Response, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from rcon import RconError, SourceRcon
import pelican_ext as pelican
import servers as srv

BASE = Path(__file__).resolve().parent
ENV_FILE = BASE / ".env"
USERS_FILE = BASE / "users.json"
# Chemins serveur : via srv.current() (multi-instances)
FILES_MAX_READ = 512 * 1024
FILES_MAX_UPLOAD = 512 * 1024 * 1024  # 512 Mo
FILES_SECRET_NAMES = {
    "rcon_password.txt",
    ".env",
    "users.txt",
    "users.json",
    "sv.db",
}
ARCHIVE_EXTS = (".rar", ".zip", ".7z", ".tar", ".tar.gz", ".tgz", ".gz")
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,32}$")
ROLES = ("admin", "user")
PBKDF2_ITERS = 200_000
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07|\x1b.")
# Codes couleurs orphelins (ESC déjà mangé) : [39m [38;2;…]m
ANSI_ORPHAN_RE = re.compile(r"\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    text = ANSI_RE.sub("", text or "")
    text = ANSI_ORPHAN_RE.sub("", text)
    return text

DEFAULT_CONFIG: dict[str, Any] = {
    "hostname": "GMod Server",
    "description": "",
    "port": 27015,
    "maxplayers": 16,
    "tickrate": 66,
    "gamemode": "sandbox",
    "map": "gm_construct",
    "workshop_collection": "",
    "workshop_start_map": "",
    "steam_api_key": "",
    "gslt": "",
    "server_password": "",
    "rcon_password": "",
    "sv_region": 3,
    "sv_lan": 0,
    "lua_refresh": 0,
    "sv_loadingurl": "",
    "sv_downloadurl": "",
    "extra_args": "",
}


def load_env() -> dict[str, str]:
    data: dict[str, str] = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip()
    return data


ENV = load_env()
PANEL_PASSWORD = ENV.get("PANEL_PASSWORD", "change-me")
SESSION_SECRET = ENV.get("SESSION_SECRET", secrets.token_hex(24)).encode()
RCON_HOST = ENV.get("RCON_HOST", "127.0.0.1")
COOKIE_NAME = "gmod_panel_session"
SESSION_TTL = 60 * 60 * 24 * 7


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS)
    return f"pbkdf2${PBKDF2_ITERS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, it_s, salt_hex, hash_hex = stored.split("$", 3)
        if algo != "pbkdf2":
            return False
        iterations = int(it_s)
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def load_users() -> list[dict[str, Any]]:
    if not USERS_FILE.exists():
        return []
    try:
        data = json.loads(USERS_FILE.read_text(encoding="utf-8"))
        users = data.get("users") if isinstance(data, dict) else data
        return list(users or [])
    except Exception:
        return []


def save_users(users: list[dict[str, Any]]) -> None:
    USERS_FILE.write_text(
        json.dumps({"users": users}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    USERS_FILE.chmod(0o600)


def find_user(username: str) -> Optional[dict[str, Any]]:
    uname = (username or "").strip().lower()
    for u in load_users():
        if str(u.get("username", "")).lower() == uname:
            return u
    return None


def ensure_users_bootstrap() -> None:
    """Crée admin depuis PANEL_PASSWORD si aucun compte."""
    if load_users():
        return
    pwd = (PANEL_PASSWORD or "change-me").strip() or "change-me"
    save_users(
        [
            {
                "username": "admin",
                "password_hash": hash_password(pwd),
                "role": "admin",
                "created_at": int(time.time()),
            }
        ]
    )


def set_user_password(username: str, new_password: str) -> None:
    new_password = (new_password or "").strip()
    if len(new_password) < 6:
        raise ValueError("mot de passe trop court (min. 6)")
    users = load_users()
    found = False
    for u in users:
        if str(u.get("username", "")).lower() == username.lower():
            u["password_hash"] = hash_password(new_password)
            found = True
            break
    if not found:
        raise ValueError("utilisateur introuvable")
    save_users(users)


def set_panel_password(new_password: str) -> None:
    """Compat : met à jour le hash du compte courant via change_password API."""
    set_user_password("admin", new_password)


ensure_users_bootstrap()
srv.ensure_migrated()


def S() -> srv.ServerCtx:
    return srv.current()


app = FastAPI(docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")

# Routes qui n'ont pas besoin d'un serveur sélectionné
_NO_SERVER_PREFIXES = (
    "/api/login",
    "/api/logout",
    "/api/me",
    "/api/admin/users",
    "/api/servers",
    "/api/password",
)


@app.middleware("http")
async def bind_server_context(request: Request, call_next):
    path = request.url.path
    token = None
    if path.startswith("/api/") and not any(path == p or path.startswith(p + "/") for p in _NO_SERVER_PREFIXES):
        sid = request.headers.get("X-Server-Id") or request.query_params.get("server_id")
        try:
            ctx = srv.get_server_by_id(sid)
        except KeyError:
            return JSONResponse({"ok": False, "error": "serveur inconnu"}, status_code=404)
        except RuntimeError as e:
            return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
        except Exception as e:
            return JSONResponse({"ok": False, "error": str(e)}, status_code=500)
        user = current_user(request)
        if user and not srv.user_can_access(ctx, str(user.get("username") or ""), str(user.get("role") or "user")):
            return JSONResponse({"ok": False, "error": "accès refusé à ce serveur"}, status_code=403)
        token = srv.set_current(ctx)
    try:
        return await call_next(request)
    finally:
        if token is not None:
            srv.reset_current(token)


def detect_public_ip() -> str:
    # Prefer primary non-loopback IPv4 from hostname -I / interfaces
    try:
        out = subprocess.check_output(["hostname", "-I"], text=True, timeout=3).strip()
        for ip in out.split():
            if ":" in ip:
                continue
            if ip.startswith("127."):
                continue
            return ip
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


PUBLIC_IP = detect_public_ip()


def load_config() -> dict[str, Any]:
    cfg = dict(DEFAULT_CONFIG)
    if S().config_file.exists():
        try:
            saved = json.loads(S().config_file.read_text(encoding="utf-8"))
            if isinstance(saved, dict):
                cfg.update({k: saved[k] for k in DEFAULT_CONFIG if k in saved})
        except Exception:
            pass
    if not cfg.get("rcon_password"):
        if S().rcon_file.exists():
            cfg["rcon_password"] = S().rcon_file.read_text().strip()
        else:
            cfg["rcon_password"] = ENV.get("RCON_PASSWORD", secrets.token_hex(12))
    # normalize types
    cfg["port"] = int(cfg.get("port") or 27015)
    cfg["maxplayers"] = int(cfg.get("maxplayers") or 16)
    cfg["tickrate"] = int(cfg.get("tickrate") or 66)
    cfg["sv_region"] = int(cfg.get("sv_region") or 3)
    cfg["sv_lan"] = int(cfg.get("sv_lan") or 0)
    cfg["lua_refresh"] = 1 if int(cfg.get("lua_refresh") or 0) else 0
    for key in (
        "hostname",
        "description",
        "gamemode",
        "map",
        "workshop_collection",
        "workshop_start_map",
        "steam_api_key",
        "gslt",
        "server_password",
        "rcon_password",
        "sv_loadingurl",
        "sv_downloadurl",
        "extra_args",
    ):
        cfg[key] = str(cfg.get(key) or "").strip()
    return cfg


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def write_start_script(cfg: dict[str, Any]) -> None:
    args = [
        "./srcds_run_x64",
        "-game garrysmod",
        "-console",
        "-usercon",
        "-ip 0.0.0.0",
        f"-port {int(cfg['port'])}",
        f"-tickrate {int(cfg['tickrate'])}",
        f"+maxplayers {int(cfg['maxplayers'])}",
        f"+gamemode {cfg['gamemode'] or 'sandbox'}",
        f"+map {cfg['map'] or 'gm_construct'}",
    ]
    collection = re.sub(r"[^0-9]", "", cfg.get("workshop_collection") or "")
    if collection:
        args.append(f"+host_workshop_collection {collection}")
    start_map = re.sub(r"[^0-9]", "", cfg.get("workshop_start_map") or "")
    if start_map:
        args.append(f"+workshop_start_map {start_map}")
    api_key = cfg.get("steam_api_key") or ""
    if api_key:
        args.append(f"-authkey {api_key}")
    gslt = cfg.get("gslt") or ""
    if gslt:
        args.append(f"+sv_setsteamaccount {gslt}")
    # Pelican: LUA_REFRESH=0 => -disableluarefresh
    if not int(cfg.get("lua_refresh") or 0):
        args.append("-disableluarefresh")
    extra = (cfg.get("extra_args") or "").strip()
    if extra:
        args.append(extra)

    body = f"#!/bin/bash\ncd {S().gmod_dir}\nexec \\\n"
    body += "  \\\n".join(f"  {a}" for a in args)
    body += ' \\\n  "$@"\n'
    S().start_sh.parent.mkdir(parents=True, exist_ok=True)
    S().start_sh.write_text(body, encoding="utf-8")
    S().start_sh.chmod(0o755)
    # ownership
    try:
        import pwd

        steam = pwd.getpwnam("steam")
        os_chown = getattr(__import__("os"), "chown")
        os_chown(S().start_sh, steam.pw_uid, steam.pw_gid)
    except Exception:
        pass


def write_server_cfg(cfg: dict[str, Any]) -> None:
    hostname = (cfg.get("hostname") or "GMod Server").replace('"', "")
    rcon = (cfg.get("rcon_password") or "").replace('"', "")
    sv_pass = (cfg.get("server_password") or "").replace('"', "")
    loading = (cfg.get("sv_loadingurl") or "").replace('"', "")
    download = (cfg.get("sv_downloadurl") or "").replace('"', "")
    content = f'''hostname "{hostname}"
rcon_password "{rcon}"
sv_password "{sv_pass}"
sv_lan {int(cfg.get("sv_lan") or 0)}
sv_region {int(cfg.get("sv_region") or 3)}
sv_maxplayers {int(cfg.get("maxplayers") or 16)}
sv_loadingurl "{loading}"
sv_downloadurl "{download}"
sbox_godmode 0
sbox_maxprops 200
sbox_maxragdolls 10
sbox_maxnpcs 10
sbox_maxballoons 10
sbox_maxeffects 10
sbox_maxemitters 5
sbox_maxthrusters 20
sbox_maxwheels 20
sbox_maxhoverballs 20
sbox_maxbuttons 20
sbox_maxsents 20
sbox_maxlamps 10
sbox_maxlights 10
sbox_maxvehicles 6
log on
sv_logfile 1
'''
    S().server_cfg.parent.mkdir(parents=True, exist_ok=True)
    S().server_cfg.write_text(content, encoding="utf-8")
    S().rcon_file.write_text(rcon + "\n", encoding="utf-8")
    try:
        import pwd

        steam = pwd.getpwnam("steam")
        os_chown = getattr(__import__("os"), "chown")
        os_chown(S().server_cfg, steam.pw_uid, steam.pw_gid)
        os_chown(S().rcon_file, steam.pw_uid, steam.pw_gid)
        S().rcon_file.chmod(0o600)
    except Exception:
        pass


def save_config(cfg: dict[str, Any]) -> dict[str, Any]:
    merged = dict(DEFAULT_CONFIG)
    merged.update(cfg)
    # sanitize
    merged["port"] = max(1, min(65535, int(merged.get("port") or 27015)))
    merged["maxplayers"] = max(1, min(128, int(merged.get("maxplayers") or 16)))
    merged["tickrate"] = max(22, min(128, int(merged.get("tickrate") or 66)))
    merged["sv_region"] = int(merged.get("sv_region") or 3)
    merged["sv_lan"] = 1 if int(merged.get("sv_lan") or 0) else 0
    merged["lua_refresh"] = 1 if int(merged.get("lua_refresh") or 0) else 0
    for key in (
        "hostname",
        "description",
        "gamemode",
        "map",
        "workshop_collection",
        "workshop_start_map",
        "steam_api_key",
        "gslt",
        "server_password",
        "rcon_password",
        "sv_loadingurl",
        "sv_downloadurl",
        "extra_args",
    ):
        merged[key] = str(merged.get(key) or "").strip()
    if not merged["rcon_password"]:
        merged["rcon_password"] = secrets.token_hex(12)
    if not merged["gamemode"]:
        merged["gamemode"] = "sandbox"
    if not merged["map"]:
        merged["map"] = "gm_construct"

    S().config_file.write_text(json.dumps(merged, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_start_script(merged)
    write_server_cfg(merged)

    # keep panel .env RCON in sync
    try:
        env_lines = []
        if ENV_FILE.exists():
            for line in ENV_FILE.read_text().splitlines():
                if line.startswith("RCON_PASSWORD=") or line.startswith("RCON_PORT="):
                    continue
                env_lines.append(line)
        env_lines.append(f"RCON_PASSWORD={merged['rcon_password']}")
        env_lines.append(f"RCON_PORT={merged['port']}")
        ENV_FILE.write_text("\n".join(env_lines).rstrip() + "\n", encoding="utf-8")
        ENV["RCON_PASSWORD"] = merged["rcon_password"]
        ENV["RCON_PORT"] = str(merged["port"])
    except Exception:
        pass

    return merged


def rcon_password() -> str:
    return load_config().get("rcon_password") or ENV.get("RCON_PASSWORD", "")


def rcon_port() -> int:
    return int(load_config().get("port") or ENV.get("RCON_PORT") or 27015)


def sign_session(ts: int, username: str, role: str, token: str) -> str:
    msg = f"{ts}:{username}:{role}:{token}"
    sig = hmac.new(SESSION_SECRET, msg.encode(), hashlib.sha256).hexdigest()
    return f"{msg}:{sig}"


def parse_session(cookie: Optional[str]) -> Optional[dict[str, Any]]:
    if not cookie:
        return None
    try:
        ts_s, username, role, token, sig = cookie.split(":", 4)
        ts = int(ts_s)
    except ValueError:
        return None
    if time.time() - ts > SESSION_TTL:
        return None
    if role not in ROLES:
        return None
    expected = hmac.new(
        SESSION_SECRET, f"{ts}:{username}:{role}:{token}".encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return None
    return {"username": username, "role": role, "ts": ts}


def valid_session(cookie: Optional[str]) -> bool:
    return parse_session(cookie) is not None


def current_user(request: Request) -> Optional[dict[str, Any]]:
    return parse_session(request.cookies.get(COOKIE_NAME))


def is_authed(request: Request) -> bool:
    return current_user(request) is not None


def require_auth(request: Request) -> Optional[JSONResponse]:
    if not is_authed(request):
        return JSONResponse({"ok": False, "error": "non authentifié"}, status_code=401)
    return None


def require_admin(request: Request) -> Optional[JSONResponse]:
    deny = require_auth(request)
    if deny:
        return deny
    user = current_user(request)
    if not user or user.get("role") != "admin":
        return JSONResponse({"ok": False, "error": "réservé aux admins"}, status_code=403)
    return None


def run_systemctl(*args: str) -> tuple[int, str]:
    proc = subprocess.run(
        ["systemctl", *args],
        capture_output=True,
        text=True,
        timeout=60,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, out.strip()


_status_rcon_cache: dict[str, tuple[float, dict]] = {}
STATUS_RCON_TTL = 15.0


def server_status(*, force_rcon: bool = False) -> dict:
    cfg = load_config()
    code, active = run_systemctl("is-active", S().unit)
    state = active.strip() if active else "unknown"
    running = state == "active"
    connect_ip = PUBLIC_IP
    connect_port = int(cfg.get("port") or 27015)
    info = {
        "ok": True,
        "running": running,
        "state": state,
        "players": None,
        "map": None,
        "hostname": cfg.get("hostname"),
        "connect_ip": connect_ip,
        "connect_port": connect_port,
        "connect": f"{connect_ip}:{connect_port}",
        "steam_connect": f"steam://connect/{connect_ip}:{connect_port}",
        "server": S().to_public(),
        "game_installed": pelican.has_gmod_bin(S().gmod_dir),
        "install": pelican.get_install_job(S().id),
    }
    if running and rcon_password():
        sid = S().id
        now = time.time()
        cached = _status_rcon_cache.get(sid)
        if not force_rcon and cached and (now - cached[0]) < STATUS_RCON_TTL:
            for k, v in cached[1].items():
                if v is not None:
                    info[k] = v
        else:
            try:
                rcon = SourceRcon(RCON_HOST, connect_port, rcon_password(), timeout=3.0)
                status = rcon.command("status")
                parsed = {"hostname": None, "map": None, "players": None}
                for line in status.splitlines():
                    low = line.lower().strip()
                    if low.startswith("hostname:"):
                        parsed["hostname"] = line.split(":", 1)[1].strip()
                    elif low.startswith("map"):
                        parsed["map"] = line.split(":", 1)[1].strip() if ":" in line else line
                    elif "players" in low and ":" in line:
                        parsed["players"] = line.split(":", 1)[1].strip()
                _status_rcon_cache[sid] = (now, parsed)
                for k, v in parsed.items():
                    if v is not None:
                        info[k] = v
            except Exception:
                pass
    else:
        _status_rcon_cache.pop(S().id, None)
    if not info.get("map"):
        info["map"] = cfg.get("map")
    return info


# Ensure config + start script exist at boot (si un serveur existe déjà)
try:
    _boot_servers = srv.list_servers()
    if _boot_servers:
        _boot = srv.set_current(_boot_servers[0])
        try:
            if not S().config_file.exists():
                save_config(load_config())
            else:
                write_start_script(load_config())
        finally:
            srv.reset_current(_boot)
except Exception:
    pass


def _spa_index() -> HTMLResponse:
    html = (BASE / "static" / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(html)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return _spa_index()


@app.get("/servers/{server_id}", response_class=HTMLResponse)
async def spa_server(server_id: str):
    """SPA : refresh / lien direct vers un serveur."""
    return _spa_index()


@app.get("/admin", response_class=HTMLResponse)
async def spa_admin():
    return _spa_index()


@app.get("/admin/users", response_class=HTMLResponse)
async def spa_admin_users():
    return _spa_index()


@app.get("/admin/servers", response_class=HTMLResponse)
async def spa_admin_servers():
    return _spa_index()


@app.post("/api/login")
async def login(
    response: Response,
    password: str = Form(...),
    username: str = Form("admin"),
):
    uname = (username or "admin").strip()
    user = find_user(uname)
    # Compat : ancien login mot-de-passe seul → compte admin
    if not user and uname == "admin" and PANEL_PASSWORD:
        if hmac.compare_digest(password, PANEL_PASSWORD):
            ensure_users_bootstrap()
            user = find_user("admin")
    if not user or not verify_password(password, str(user.get("password_hash") or "")):
        return JSONResponse({"ok": False, "error": "identifiants incorrects"}, status_code=403)
    role = user.get("role") if user.get("role") in ROLES else "user"
    cookie = sign_session(int(time.time()), str(user["username"]), str(role), secrets.token_hex(16))
    resp = JSONResponse(
        {"ok": True, "username": user["username"], "role": role}
    )
    resp.set_cookie(
        COOKIE_NAME,
        cookie,
        httponly=True,
        samesite="lax",
        max_age=SESSION_TTL,
        path="/",
    )
    return resp


@app.post("/api/logout")
async def logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


@app.post("/api/password")
async def change_password(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    me = current_user(request)
    assert me
    body = await request.json()
    current = str(body.get("current") or "")
    new_password = str(body.get("new_password") or "")
    confirm = str(body.get("confirm") or "")
    user = find_user(me["username"])
    if not user or not verify_password(current, str(user.get("password_hash") or "")):
        return JSONResponse({"ok": False, "error": "mot de passe actuel incorrect"}, status_code=403)
    if new_password != confirm:
        return JSONResponse({"ok": False, "error": "la confirmation ne correspond pas"}, status_code=400)
    try:
        set_user_password(me["username"], new_password)
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    return {"ok": True, "message": "Mot de passe mis à jour"}


@app.get("/api/me")
async def me(request: Request):
    user = current_user(request)
    if not user:
        return {"ok": True, "authed": False}
    return {
        "ok": True,
        "authed": True,
        "username": user["username"],
        "role": user["role"],
    }


@app.get("/api/servers")
async def servers_list(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    user = current_user(request) or {}
    rows = []
    for s in srv.list_servers_for(str(user.get("username") or ""), str(user.get("role") or "user")):
        token = srv.set_current(s)
        try:
            code, active = run_systemctl("is-active", s.unit)
            state = (active or "unknown").strip()
            cfg = load_config()
            rows.append(
                {
                    **s.to_public(),
                    "state": state,
                    "running": state == "active",
                    "port": int(cfg.get("port") or 27015),
                    "hostname": cfg.get("hostname") or s.name,
                    "map": cfg.get("map") or "",
                    "game_installed": pelican.has_gmod_bin(s.gmod_dir),
                    "install": pelican.get_install_job(s.id),
                }
            )
        finally:
            srv.reset_current(token)
    return {"ok": True, "servers": rows}


@app.post("/api/servers")
async def servers_create(request: Request):
    deny = require_admin(request)
    if deny:
        return deny
    body = await request.json()
    sid = str(body.get("id") or "").strip().lower()
    name = str(body.get("name") or "").strip()
    gmod_dir = str(body.get("gmod_dir") or "").strip()
    unit = str(body.get("unit") or "").strip()
    owner = str(body.get("owner") or "").strip()
    if owner and not find_user(owner):
        return JSONResponse({"ok": False, "error": "utilisateur inconnu"}, status_code=400)
    try:
        port = int(body.get("port") or 27015)
    except Exception:
        port = 27015
    try:
        ctx = srv.create_server(
            server_id=sid,
            name=name,
            gmod_dir="",
            unit=unit or f"gmod-{sid}",
            port=port,
            owner=owner,
        )
        token = srv.set_current(ctx)
        install_note = ""
        try:
            cfg = dict(DEFAULT_CONFIG)
            cfg["port"] = port
            cfg["hostname"] = name or sid
            save_config(cfg)
            write_start_script(cfg)
            write_server_cfg(cfg)
            # Install GMod en arrière-plan (SteamCMD ou clone)
            job = pelican.start_gmod_install(ctx.id, ctx.gmod_dir, lambda d: srv.install_gmod(d))
            if job.get("status") == "ok":
                install_note = f" + {job.get('detail') or 'installé'}"
            elif job.get("status") == "running":
                install_note = " — installation GMod lancée (SteamCMD, 5–20 min)"
            else:
                install_note = f" — install: {job.get('detail') or 'erreur'}"
        finally:
            srv.reset_current(token)
        pelican.log_activity("server.create", f"{ctx.id} owner={ctx.owner or '-'}", True)
        return {
            "ok": True,
            "server": ctx.to_public(),
            "install": pelican.get_install_job(ctx.id),
            "message": f"Serveur {ctx.id} créé{install_note}",
        }
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.patch("/api/servers/{server_id}")
async def servers_patch(request: Request, server_id: str):
    deny = require_admin(request)
    if deny:
        return deny
    body = await request.json()
    name = body.get("name", None)
    owner = body.get("owner", None)
    if name is not None:
        name = str(name).strip()
    if owner is not None:
        owner = str(owner).strip()
        if owner and not find_user(owner):
            return JSONResponse({"ok": False, "error": "utilisateur inconnu"}, status_code=400)
    try:
        if name is not None and owner is None:
            ctx = srv.rename_server(server_id, name)
        else:
            ctx = srv.update_server(server_id, name=name, owner=owner)
        pelican.log_activity("server.patch", f"{server_id} name={ctx.name} owner={ctx.owner or '-'}", True)
        return {
            "ok": True,
            "server": ctx.to_public(),
            "message": f"Serveur mis à jour · user {ctx.owner or '—'}",
        }
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    except KeyError:
        return JSONResponse({"ok": False, "error": "introuvable"}, status_code=404)
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.delete("/api/servers/{server_id}")
async def servers_delete(request: Request, server_id: str):
    deny = require_admin(request)
    if deny:
        return deny
    try:
        srv.delete_server(server_id, remove_files=True)
        pelican.log_activity("server.delete", f"{server_id} (wipe)", True)
        return {
            "ok": True,
            "message": f"Serveur {server_id} supprimé (fichiers + service)",
        }
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    except KeyError:
        return JSONResponse({"ok": False, "error": "introuvable"}, status_code=404)
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/api/admin/users")
async def admin_list_users(request: Request):
    deny = require_admin(request)
    if deny:
        return deny
    users = [
        {
            "username": u.get("username"),
            "role": u.get("role", "user"),
            "created_at": u.get("created_at"),
        }
        for u in load_users()
    ]
    return {"ok": True, "users": users}


@app.post("/api/admin/users")
async def admin_create_user(request: Request):
    deny = require_admin(request)
    if deny:
        return deny
    body = await request.json()
    username = str(body.get("username") or "").strip()
    password = str(body.get("password") or "")
    role = str(body.get("role") or "user").strip().lower()
    if not USERNAME_RE.match(username):
        return JSONResponse(
            {"ok": False, "error": "username invalide (3–32, a-z 0-9 _ -)"},
            status_code=400,
        )
    if role not in ROLES:
        return JSONResponse({"ok": False, "error": "rôle invalide"}, status_code=400)
    if len(password) < 6:
        return JSONResponse({"ok": False, "error": "mot de passe trop court (min. 6)"}, status_code=400)
    if find_user(username):
        return JSONResponse({"ok": False, "error": "utilisateur déjà existant"}, status_code=400)
    users = load_users()
    users.append(
        {
            "username": username,
            "password_hash": hash_password(password),
            "role": role,
            "created_at": int(time.time()),
        }
    )
    save_users(users)
    pelican.log_activity("admin", f"compte créé : {username} ({role})")
    return {"ok": True, "message": f"Compte {username} créé"}


@app.delete("/api/admin/users/{username}")
async def admin_delete_user(request: Request, username: str):
    deny = require_admin(request)
    if deny:
        return deny
    me = current_user(request)
    assert me
    if username.lower() == me["username"].lower():
        return JSONResponse({"ok": False, "error": "tu ne peux pas te supprimer"}, status_code=400)
    users = load_users()
    admins = [u for u in users if u.get("role") == "admin"]
    target = next((u for u in users if str(u.get("username", "")).lower() == username.lower()), None)
    if not target:
        return JSONResponse({"ok": False, "error": "introuvable"}, status_code=404)
    if target.get("role") == "admin" and len(admins) <= 1:
        return JSONResponse({"ok": False, "error": "il doit rester au moins 1 admin"}, status_code=400)
    users = [u for u in users if str(u.get("username", "")).lower() != username.lower()]
    save_users(users)
    pelican.log_activity("admin", f"compte supprimé : {username}")
    return {"ok": True, "message": f"Compte {username} supprimé"}


@app.post("/api/admin/users/{username}/password")
async def admin_reset_password(request: Request, username: str):
    deny = require_admin(request)
    if deny:
        return deny
    body = await request.json()
    new_password = str(body.get("password") or "")
    try:
        set_user_password(username, new_password)
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    pelican.log_activity("admin", f"mdp réinitialisé : {username}")
    return {"ok": True, "message": f"Mot de passe de {username} mis à jour"}


@app.get("/api/status")
async def status(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    return server_status()


@app.get("/api/config")
async def get_config(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    cfg = load_config()
    return {
        "ok": True,
        "config": cfg,
        "connect_ip": PUBLIC_IP,
        "connect": f"{PUBLIC_IP}:{cfg['port']}",
        "steam_connect": f"steam://connect/{PUBLIC_IP}:{cfg['port']}",
    }


@app.post("/api/config")
async def post_config(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    body = await request.json()
    restart = bool(body.pop("restart", False))
    current = load_config()
    incoming = body.get("config") if isinstance(body.get("config"), dict) else body
    for key in DEFAULT_CONFIG:
        if key in incoming:
            current[key] = incoming[key]
    saved = save_config(current)
    out = ""
    if restart:
        code, out = run_systemctl("restart", S().unit)
        ok = code == 0
    else:
        ok = True
    return {
        "ok": ok,
        "config": saved,
        "output": out,
        "restarted": restart,
        "connect": f"{PUBLIC_IP}:{saved['port']}",
        "status": server_status(),
        "message": "Config enregistrée"
        + (" et serveur redémarré" if restart else " (redémarre pour appliquer workshop/API)"),
    }


@app.post("/api/start")
async def start(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    ctx = S()
    if not pelican.has_gmod_bin(ctx.gmod_dir):
        job = pelican.get_install_job(ctx.id)
        if job.get("status") != "running":
            pelican.start_gmod_install(ctx.id, ctx.gmod_dir, lambda d: srv.install_gmod(d))
            job = pelican.get_install_job(ctx.id)
        detail = job.get("detail") or "installation…"
        if job.get("status") == "error":
            return JSONResponse(
                {
                    "ok": False,
                    "error": f"GMod non installé: {detail}",
                    "status": server_status(),
                    "install": job,
                },
                status_code=400,
            )
        return JSONResponse(
            {
                "ok": False,
                "error": f"GMod pas encore prêt ({detail}). Réessaie Start dans quelques minutes.",
                "status": server_status(),
                "install": job,
            },
            status_code=409,
        )
    write_start_script(load_config())
    write_server_cfg(load_config())
    code, out = run_systemctl("start", ctx.unit)
    pelican.log_activity("power.start", out[:200], code == 0)
    return {"ok": code == 0, "output": out, "status": server_status()}


@app.post("/api/install")
async def install_game(request: Request):
    """Relance l'installation GMod (SteamCMD / clone) pour le serveur courant."""
    deny = require_auth(request)
    if deny:
        return deny
    ctx = S()
    job = pelican.start_gmod_install(ctx.id, ctx.gmod_dir, lambda d: srv.install_gmod(d))
    return {
        "ok": True,
        "message": "Installation GMod lancée" if job.get("status") == "running" else job.get("detail") or "OK",
        "install": job,
        "status": server_status(),
    }


@app.post("/api/stop")
async def stop(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    code, out = run_systemctl("stop", S().unit)
    pelican.log_activity("power.stop", out[:200], code == 0)
    return {"ok": code == 0, "output": out, "status": server_status()}


@app.post("/api/restart")
async def restart(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    ctx = S()
    if not pelican.has_gmod_bin(ctx.gmod_dir):
        return JSONResponse(
            {"ok": False, "error": "GMod non installé — lance Start ou Installer d’abord", "status": server_status()},
            status_code=400,
        )
    write_start_script(load_config())
    write_server_cfg(load_config())
    code, out = run_systemctl("restart", ctx.unit)
    pelican.log_activity("power.restart", out[:200], code == 0)
    return {"ok": code == 0, "output": out, "status": server_status()}


@app.post("/api/kill")
async def kill(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    code, out = pelican.kill_gmod(S().unit)
    return {"ok": True, "output": out, "status": server_status(), "message": "Kill forcé"}


@app.get("/api/resources")
async def resources(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    return pelican.resources_snapshot()


@app.get("/api/activity")
async def activity(request: Request, limit: int = 40):
    deny = require_auth(request)
    if deny:
        return deny
    return {"ok": True, "entries": pelican.read_activity(limit)}


@app.get("/api/backups")
async def backups_list(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    return {"ok": True, "backups": pelican.list_backups(backup_dir=S().backup_dir)}


@app.post("/api/backups")
async def backups_create(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    body = await request.json()
    note = str(body.get("note") or "")
    try:
        info = pelican.create_backup(note, gmod_dir=S().gmod_dir, backup_dir=S().backup_dir)
        return {
            "ok": True,
            "backup": info,
            "backups": pelican.list_backups(backup_dir=S().backup_dir),
            "message": f"Backup créé: {info['name']}",
        }
    except Exception as e:
        pelican.log_activity("backup.create", str(e), False)
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.post("/api/backups/delete")
async def backups_delete(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    body = await request.json()
    name = str(body.get("name") or "")
    try:
        pelican.delete_backup(name, backup_dir=S().backup_dir)
        return {"ok": True, "backups": pelican.list_backups(backup_dir=S().backup_dir), "message": "Backup supprimé"}
    except FileNotFoundError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=404)
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@app.post("/api/backups/restore")
async def backups_restore(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    body = await request.json()
    name = str(body.get("name") or "")
    run_systemctl("stop", S().unit)
    try:
        pelican.restore_backup(name, gmod_dir=S().gmod_dir, backup_dir=S().backup_dir)
        return {
            "ok": True,
            "message": "Backup restauré — redémarre le serveur",
            "status": server_status(),
            "backups": pelican.list_backups(backup_dir=S().backup_dir),
        }
    except Exception as e:
        pelican.log_activity("backup.restore", str(e), False)
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.post("/api/update")
async def update_game(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    validate = bool((body or {}).get("validate", True))
    run_systemctl("stop", S().unit)
    try:
        out = pelican.steamcmd_update(validate=validate, gmod_dir=S().gmod_dir)
        return {"ok": True, "message": "Mise à jour SteamCMD terminée", "output": out[-1500:], "status": server_status()}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.post("/api/changelevel")
async def changelevel(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    body = await request.json()
    mapname = re.sub(r"[^a-zA-Z0-9_\-]", "", str(body.get("map") or "").strip())
    if not mapname:
        return JSONResponse({"ok": False, "error": "map requise"}, status_code=400)
    if not server_status()["running"]:
        return JSONResponse({"ok": False, "error": "serveur arrêté"}, status_code=400)
    try:
        rcon = SourceRcon(RCON_HOST, rcon_port(), rcon_password(), timeout=8.0)
        result = rcon.command(f"changelevel {mapname}")
        pelican.log_activity("rcon.changelevel", mapname, True)
        return {"ok": True, "result": result or "ok", "message": f"Changelevel {mapname}"}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.post("/api/cmd")
async def cmd(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    body = await request.json()
    command = (body.get("command") or "").strip()
    if not command:
        return JSONResponse({"ok": False, "error": "commande vide"}, status_code=400)
    if not server_status()["running"]:
        return JSONResponse({"ok": False, "error": "serveur arrêté"}, status_code=400)
    try:
        rcon = SourceRcon(RCON_HOST, rcon_port(), rcon_password(), timeout=8.0)
        result = rcon.command(command)
        return {"ok": True, "result": result or "(ok, pas de réponse)"}
    except RconError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"RCON: {e}"}, status_code=500)


def read_players_payload() -> dict:
    default_ranks = [
        {"id": "user", "label": "Joueur"},
        {"id": "admin", "label": "Admin"},
        {"id": "superadmin", "label": "SuperAdmin"},
    ]
    players: list[dict] = []
    ranks = default_ranks
    updated = None
    stale = False
    if S().players_json.exists():
        try:
            data = json.loads(S().players_json.read_text(encoding="utf-8"))
            players = data.get("players") or []
            updated = data.get("updated")
            # Si le serveur a hiberné, le JSON peut rester bloqué avec d'anciens joueurs
            if updated is not None:
                try:
                    age = time.time() - float(updated)
                    if age > 20:
                        players = []
                        stale = True
                except (TypeError, ValueError):
                    pass
        except Exception:
            pass
    if S().ranks_json.exists():
        try:
            data = json.loads(S().ranks_json.read_text(encoding="utf-8"))
            if data.get("ranks"):
                ranks = data["ranks"]
        except Exception:
            pass

    # Double check via status (si serveur vide -> liste vide)
    if players:
        try:
            info = server_status()
            if info.get("running"):
                raw = (info.get("players") or "").lower()
                if "0 humans" in raw or raw.startswith("0 /") or raw.startswith("0/"):
                    players = []
                    stale = True
        except Exception:
            pass

    return {
        "ok": True,
        "players": players,
        "count": len(players),
        "ranks": ranks,
        "updated": updated,
        "stale": stale,
    }


@app.get("/api/players")
async def get_players(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    return read_players_payload()


@app.post("/api/players/rank")
async def set_player_rank(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    if not server_status()["running"]:
        return JSONResponse({"ok": False, "error": "serveur arrêté"}, status_code=400)
    body = await request.json()
    steamid = str(body.get("steamid") or "").strip()
    steamid64 = str(body.get("steamid64") or "").strip()
    rank = str(body.get("rank") or "").strip().lower()
    if not rank or not re.match(r"^[a-z0-9_\-]{2,32}$", rank):
        return JSONResponse({"ok": False, "error": "grade invalide"}, status_code=400)

    # Prefer SteamID64 (no ':' for RCON tokenizer)
    target_id = steamid64
    if not re.match(r"^\d{15,20}$", target_id or ""):
        target_id = ""
    if not target_id and re.match(r"^STEAM_[0-5]:[01]:\d+$", steamid, re.I):
        # fallback: quote steamid
        target_id = steamid

    if not target_id:
        return JSONResponse({"ok": False, "error": "steamid64/steamid manquant"}, status_code=400)

    try:
        rcon = SourceRcon(RCON_HOST, rcon_port(), rcon_password(), timeout=8.0)
        if target_id.startswith("STEAM_"):
            result = rcon.command(f'cloudix_setrank "{target_id}" {rank}')
        else:
            result = rcon.command(f"cloudix_setrank {target_id} {rank}")
        time.sleep(0.5)
        payload = read_players_payload()
        return {
            "ok": True,
            "message": f"Grade {rank} appliqué",
            "result": result,
            "players": payload["players"],
            "ranks": payload["ranks"],
        }
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.post("/api/players/kick")
async def kick_player(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    if not server_status()["running"]:
        return JSONResponse({"ok": False, "error": "serveur arrêté"}, status_code=400)
    body = await request.json()
    steamid = str(body.get("steamid") or "").strip()
    steamid64 = str(body.get("steamid64") or "").strip()
    reason = str(body.get("reason") or "Kick panel X").strip()[:80]
    target_id = steamid64 if re.match(r"^\d{15,20}$", steamid64 or "") else ""
    if not target_id and re.match(r"^STEAM_[0-5]:[01]:\d+$", steamid, re.I):
        target_id = steamid
    if not target_id:
        return JSONResponse({"ok": False, "error": "steamid64/steamid manquant"}, status_code=400)
    reason_safe = re.sub(r"[^\w\s\-.,!?àâäéèêëïîôùûüçÀÂÄÉÈÊËÏÎÔÙÛÜÇ]", "", reason) or "Kick"
    try:
        rcon = SourceRcon(RCON_HOST, rcon_port(), rcon_password(), timeout=8.0)
        if target_id.startswith("STEAM_"):
            result = rcon.command(f'cloudix_kick "{target_id}" {reason_safe}')
        else:
            result = rcon.command(f"cloudix_kick {target_id} {reason_safe}")
        time.sleep(0.3)
        payload = read_players_payload()
        return {"ok": True, "message": "Joueur kick", "result": result, "players": payload["players"]}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


def files_safe_resolve(rel: str) -> Path:
    rel = (rel or "").replace("\\", "/").strip()
    while rel.startswith("./"):
        rel = rel[2:]
    if rel in ("", "/"):
        rel = "."
    rel = rel.lstrip("/")
    root = S().files_root.resolve()
    target = (root / rel).resolve()
    if target != root and root not in target.parents:
        raise PermissionError("chemin hors zone")
    return target


def files_rel_of(path: Path) -> str:
    root = S().files_root.resolve()
    path = path.resolve()
    if path == root:
        return ""
    return str(path.relative_to(root)).replace("\\", "/")


def files_is_text_name(name: str) -> bool:
    low = name.lower()
    exts = (
        ".txt", ".cfg", ".lua", ".json", ".yml", ".yaml", ".ini", ".xml",
        ".md", ".log", ".vmt", ".vdf", ".res", ".properties", ".sh", ".py",
        ".css", ".js", ".html", ".htm", ".csv", ".toml", ".env",
    )
    return low.endswith(exts) or low in ("server.cfg", "autoexec.cfg", "motd.txt")


@app.get("/api/files")
async def list_files(request: Request, path: str = ""):
    deny = require_auth(request)
    if deny:
        return deny
    try:
        target = files_safe_resolve(path)
    except PermissionError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=403)
    if not target.exists():
        return JSONResponse({"ok": False, "error": "introuvable"}, status_code=404)
    if not target.is_dir():
        return JSONResponse({"ok": False, "error": "pas un dossier"}, status_code=400)

    entries = []
    try:
        children = list(target.iterdir())
    except PermissionError:
        return JSONResponse({"ok": False, "error": "permission refusée"}, status_code=403)

    children.sort(key=lambda p: (not p.is_dir(), p.name.lower()))
    for child in children:
        try:
            st = child.stat()
            entries.append({
                "name": child.name,
                "path": files_rel_of(child),
                "type": "dir" if child.is_dir() else "file",
                "size": 0 if child.is_dir() else int(st.st_size),
                "mtime": int(st.st_mtime),
                "secret": child.name.lower() in FILES_SECRET_NAMES or child.name.startswith(".env"),
                "archive": (not child.is_dir()) and files_is_archive(child.name),
            })
        except OSError:
            continue

    rel = files_rel_of(target)
    parent = ""
    if rel:
        parent_path = target.parent
        parent = files_rel_of(parent_path)

    crumbs = [{"name": "gmod", "path": ""}]
    if rel:
        acc = []
        for part in rel.split("/"):
            acc.append(part)
            crumbs.append({"name": part, "path": "/".join(acc)})

    return {
        "ok": True,
        "root": str(S().files_root),
        "path": rel,
        "parent": parent,
        "crumbs": crumbs,
        "entries": entries,
        "count": len(entries),
    }


@app.get("/api/files/read")
async def read_file(request: Request, path: str = ""):
    deny = require_auth(request)
    if deny:
        return deny
    try:
        target = files_safe_resolve(path)
    except PermissionError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=403)
    if not target.exists() or not target.is_file():
        return JSONResponse({"ok": False, "error": "fichier introuvable"}, status_code=404)

    name = target.name
    size = target.stat().st_size
    secret = name.lower() in FILES_SECRET_NAMES or name.startswith(".env")
    if secret:
        return {
            "ok": True,
            "path": files_rel_of(target),
            "name": name,
            "size": size,
            "truncated": False,
            "binary": False,
            "secret": True,
            "content": "*** fichier sensible masqué ***",
        }

    if size > FILES_MAX_READ:
        raw = target.read_bytes()[:FILES_MAX_READ]
        truncated = True
    else:
        raw = target.read_bytes()
        truncated = False

    # detect binary
    if b"\x00" in raw[:4096] or not files_is_text_name(name):
        # still try utf-8 for unknown extensions if printable
        try:
            text = raw.decode("utf-8")
            if sum(1 for c in text[:2000] if ord(c) < 9) > 5:
                raise UnicodeError()
        except Exception:
            return {
                "ok": True,
                "path": files_rel_of(target),
                "name": name,
                "size": size,
                "truncated": truncated,
                "binary": True,
                "secret": False,
                "content": f"(fichier binaire — {size} octets)",
            }
    else:
        text = raw.decode("utf-8", errors="replace")

    # Redact secrets in text previews
    redacted = False
    def _redact_line(line: str) -> str:
        nonlocal redacted
        low = line.lower()
        keys = ("rcon_password", "sv_password", "password", "authkey", "gslt", "steam_api", "api_key", "token")
        if any(k in low for k in keys) and ("=" in line or '"' in line or "'" in line):
            redacted = True
            if "=" in line:
                left = line.split("=", 1)[0]
                return f'{left}= "***"'
            return "***"
        return line

    text = "\n".join(_redact_line(line) for line in text.splitlines())
    if truncated:
        text += "\n\n… [fichier tronqué]"

    return {
        "ok": True,
        "path": files_rel_of(target),
        "name": name,
        "size": size,
        "truncated": truncated,
        "binary": False,
        "secret": False,
        "redacted": redacted,
        "content": text,
    }


def files_sanitize_name(name: str) -> str:
    name = Path(name).name
    name = re.sub(r"[^\w.\- ()\[\]]+", "_", name, flags=re.UNICODE)
    name = name.strip(" .")
    if not name or name in (".", ".."):
        raise ValueError("nom de fichier invalide")
    return name


def files_is_archive(name: str) -> bool:
    low = name.lower()
    return any(low.endswith(ext) for ext in ARCHIVE_EXTS)


@app.post("/api/files/delete")
async def delete_file(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    body = await request.json()
    rel = str(body.get("path") or "").strip()
    if not rel:
        return JSONResponse({"ok": False, "error": "chemin requis"}, status_code=400)
    try:
        target = files_safe_resolve(rel)
    except PermissionError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=403)

    root = S().files_root.resolve()
    if target == root:
        return JSONResponse({"ok": False, "error": "impossible de supprimer la racine"}, status_code=400)
    if not target.exists():
        return JSONResponse({"ok": False, "error": "introuvable"}, status_code=404)

    parent_rel = files_rel_of(target.parent)
    name = target.name
    try:
        if target.is_dir():
            shutil.rmtree(target)
            kind = "dossier"
        else:
            target.unlink()
            kind = "fichier"
    except PermissionError:
        return JSONResponse({"ok": False, "error": "permission refusée"}, status_code=403)
    except OSError as e:
        return JSONResponse({"ok": False, "error": f"suppression échouée: {e}"}, status_code=500)

    return {
        "ok": True,
        "message": f"{kind.capitalize()} supprimé: {name}",
        "dir": parent_rel,
        "name": name,
    }


@app.post("/api/files/upload")
async def upload_file(
    request: Request,
    path: str = Form(""),
    file: UploadFile = File(...),
):
    deny = require_auth(request)
    if deny:
        return deny
    try:
        dest_dir = files_safe_resolve(path)
    except PermissionError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=403)
    if not dest_dir.exists() or not dest_dir.is_dir():
        return JSONResponse({"ok": False, "error": "dossier cible invalide"}, status_code=400)

    try:
        safe_name = files_sanitize_name(file.filename or "upload.bin")
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)

    dest = dest_dir / safe_name
    # avoid overwrite by suffixing
    if dest.exists():
        stem = dest.stem
        suffix = dest.suffix
        i = 1
        while True:
            candidate = dest_dir / f"{stem}_{i}{suffix}"
            if not candidate.exists():
                dest = candidate
                safe_name = dest.name
                break
            i += 1

    total = 0
    try:
        with dest.open("wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > FILES_MAX_UPLOAD:
                    out.close()
                    dest.unlink(missing_ok=True)
                    return JSONResponse(
                        {"ok": False, "error": "fichier trop volumineux (max 512 Mo)"},
                        status_code=413,
                    )
                out.write(chunk)
    except Exception as e:
        dest.unlink(missing_ok=True)
        return JSONResponse({"ok": False, "error": f"upload échoué: {e}"}, status_code=500)
    finally:
        await file.close()

    try:
        import pwd

        steam = pwd.getpwnam("steam")
        os_chown = getattr(__import__("os"), "chown")
        os_chown(dest, steam.pw_uid, steam.pw_gid)
    except Exception:
        pass

    return {
        "ok": True,
        "message": f"Upload OK: {safe_name}",
        "path": files_rel_of(dest),
        "name": safe_name,
        "size": total,
        "archive": files_is_archive(safe_name),
        "dir": files_rel_of(dest_dir),
    }


@app.post("/api/files/extract")
async def extract_file(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    body = await request.json()
    rel = str(body.get("path") or "").strip()
    try:
        archive = files_safe_resolve(rel)
    except PermissionError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=403)
    if not archive.exists() or not archive.is_file():
        return JSONResponse({"ok": False, "error": "archive introuvable"}, status_code=404)
    if not files_is_archive(archive.name):
        return JSONResponse({"ok": False, "error": "format non supporté (.rar .zip .7z …)"}, status_code=400)

    out_dir = archive.parent
    low = archive.name.lower()
    try:
        if low.endswith(".zip"):
            cmd = ["unzip", "-o", str(archive), "-d", str(out_dir)]
        elif low.endswith(".rar"):
            # 7z gère mieux que unrar-free pour beaucoup de rar
            cmd = ["7z", "x", f"-o{out_dir}", "-y", str(archive)]
        elif low.endswith(".7z") or low.endswith(".tar") or low.endswith(".tar.gz") or low.endswith(".tgz") or low.endswith(".gz"):
            cmd = ["7z", "x", f"-o{out_dir}", "-y", str(archive)]
        else:
            cmd = ["7z", "x", f"-o{out_dir}", "-y", str(archive)]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        if proc.returncode != 0:
            # fallback unrar for rar
            if low.endswith(".rar"):
                proc2 = subprocess.run(
                    ["unrar", "x", "-o+", str(archive), str(out_dir) + "/"],
                    capture_output=True,
                    text=True,
                    timeout=600,
                )
                out2 = ((proc2.stdout or "") + "\n" + (proc2.stderr or "")).strip()
                if proc2.returncode != 0:
                    return JSONResponse(
                        {
                            "ok": False,
                            "error": "extraction échouée",
                            "output": (out + "\n" + out2)[-2000:],
                        },
                        status_code=500,
                    )
                out = out2
            else:
                return JSONResponse(
                    {"ok": False, "error": "extraction échouée", "output": out[-2000:]},
                    status_code=500,
                )

        # fix ownership of extracted tree (best effort, shallow)
        try:
            import pwd

            steam = pwd.getpwnam("steam")
            os_chown = getattr(__import__("os"), "chown")
            for p in out_dir.rglob("*"):
                try:
                    os_chown(p, steam.pw_uid, steam.pw_gid)
                except Exception:
                    pass
        except Exception:
            pass

        return {
            "ok": True,
            "message": f"Extrait dans {files_rel_of(out_dir) or 'gmod/'}",
            "dir": files_rel_of(out_dir),
            "output": out[-1500:],
        }
    except subprocess.TimeoutExpired:
        return JSONResponse({"ok": False, "error": "extraction trop longue"}, status_code=500)
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/api/files/download")
async def download_file(request: Request, path: str = ""):
    deny = require_auth(request)
    if deny:
        return deny
    try:
        target = files_safe_resolve(path)
    except PermissionError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=403)
    if not target.exists() or not target.is_file():
        return JSONResponse({"ok": False, "error": "fichier introuvable"}, status_code=404)
    return FileResponse(path=str(target), filename=target.name, media_type="application/octet-stream")


@app.post("/api/files/save")
async def save_file(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    body = await request.json()
    rel = str(body.get("path") or "").strip()
    content = body.get("content")
    if content is None:
        return JSONResponse({"ok": False, "error": "content manquant"}, status_code=400)
    try:
        target = files_safe_resolve(rel)
    except PermissionError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=403)
    if target.name.lower() in FILES_SECRET_NAMES or target.name.startswith(".env"):
        return JSONResponse({"ok": False, "error": "fichier sensible protégé"}, status_code=403)
    if target.exists() and target.is_dir():
        return JSONResponse({"ok": False, "error": "cible est un dossier"}, status_code=400)
    target.parent.mkdir(parents=True, exist_ok=True)
    text = str(content)
    if len(text.encode("utf-8")) > FILES_MAX_UPLOAD:
        return JSONResponse({"ok": False, "error": "contenu trop volumineux"}, status_code=413)
    target.write_text(text, encoding="utf-8")
    try:
        import pwd

        steam = pwd.getpwnam("steam")
        os.chown(target, steam.pw_uid, steam.pw_gid)
    except Exception:
        pass
    pelican.log_activity("files.save", files_rel_of(target), True)
    return {"ok": True, "message": f"Enregistré: {target.name}", "path": files_rel_of(target)}


@app.post("/api/files/mkdir")
async def mkdir_file(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    body = await request.json()
    parent = str(body.get("path") or "").strip()
    name = str(body.get("name") or "").strip()
    try:
        safe_name = files_sanitize_name(name)
        dest_dir = files_safe_resolve(parent)
    except (PermissionError, ValueError) as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    if not dest_dir.exists() or not dest_dir.is_dir():
        return JSONResponse({"ok": False, "error": "dossier parent invalide"}, status_code=400)
    new = dest_dir / safe_name
    if new.exists():
        return JSONResponse({"ok": False, "error": "existe déjà"}, status_code=400)
    new.mkdir(parents=False)
    try:
        import pwd

        steam = pwd.getpwnam("steam")
        os.chown(new, steam.pw_uid, steam.pw_gid)
    except Exception:
        pass
    pelican.log_activity("files.mkdir", files_rel_of(new), True)
    return {"ok": True, "message": f"Dossier créé: {safe_name}", "dir": files_rel_of(dest_dir)}


@app.post("/api/files/rename")
async def rename_file(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    body = await request.json()
    rel = str(body.get("path") or "").strip()
    new_name = str(body.get("name") or "").strip()
    try:
        target = files_safe_resolve(rel)
        safe_name = files_sanitize_name(new_name)
    except (PermissionError, ValueError) as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    if target == S().files_root.resolve():
        return JSONResponse({"ok": False, "error": "impossible de renommer la racine"}, status_code=400)
    if not target.exists():
        return JSONResponse({"ok": False, "error": "introuvable"}, status_code=404)
    dest = target.parent / safe_name
    if dest.exists():
        return JSONResponse({"ok": False, "error": "cible existe déjà"}, status_code=400)
    target.rename(dest)
    pelican.log_activity("files.rename", f"{rel} -> {safe_name}", True)
    return {"ok": True, "message": f"Renommé: {safe_name}", "dir": files_rel_of(dest.parent), "path": files_rel_of(dest)}


@app.post("/api/files/compress")
async def compress_file(request: Request):
    deny = require_auth(request)
    if deny:
        return deny
    body = await request.json()
    rel = str(body.get("path") or "").strip()
    try:
        target = files_safe_resolve(rel)
    except PermissionError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=403)
    if not target.exists():
        return JSONResponse({"ok": False, "error": "introuvable"}, status_code=404)
    if target == S().files_root.resolve():
        return JSONResponse({"ok": False, "error": "impossible de compresser la racine"}, status_code=400)
    zip_name = target.name + ".zip"
    dest = target.parent / zip_name
    i = 1
    while dest.exists():
        dest = target.parent / f"{target.name}_{i}.zip"
        i += 1
    if target.is_dir():
        cmd = ["zip", "-r", str(dest), target.name]
        cwd = str(target.parent)
    else:
        cmd = ["zip", "-j", str(dest), str(target)]
        cwd = str(target.parent)
    # zip may be missing — fallback to 7z
    if shutil.which("zip"):
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=600)
    else:
        proc = subprocess.run(
            ["7z", "a", "-tzip", str(dest), str(target)],
            capture_output=True,
            text=True,
            timeout=600,
        )
    if proc.returncode != 0 or not dest.exists():
        return JSONResponse(
            {"ok": False, "error": "compression échouée", "output": ((proc.stdout or "") + proc.stderr)[-1000:]},
            status_code=500,
        )
    try:
        import pwd

        steam = pwd.getpwnam("steam")
        os.chown(dest, steam.pw_uid, steam.pw_gid)
    except Exception:
        pass
    pelican.log_activity("files.compress", files_rel_of(dest), True)
    return {
        "ok": True,
        "message": f"Archive: {dest.name}",
        "path": files_rel_of(dest),
        "dir": files_rel_of(dest.parent),
    }


@app.websocket("/ws/console")
async def ws_console(websocket: WebSocket):
    await websocket.accept()
    cookie = websocket.cookies.get(COOKIE_NAME)
    if not valid_session(cookie):
        await websocket.send_json({"type": "error", "data": "non authentifié"})
        await websocket.close()
        return

    sid = websocket.query_params.get("server_id")
    try:
        ctx = srv.get_server_by_id(sid)
    except Exception as e:
        await websocket.send_json({"type": "error", "data": str(e)})
        await websocket.close()
        return
    sess = parse_session(cookie) or {}
    if not srv.user_can_access(ctx, str(sess.get("username") or ""), str(sess.get("role") or "user")):
        await websocket.send_json({"type": "error", "data": "accès refusé à ce serveur"})
        await websocket.close()
        return
    token = srv.set_current(ctx)
    await websocket.send_json({"type": "info", "data": f"Console · {ctx.name} ({ctx.id})"})
    proc = await asyncio.create_subprocess_exec(
        "journalctl",
        "-u",
        ctx.unit,
        "-f",
        "-n",
        "120",
        "--no-pager",
        "-o",
        "cat",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env={**os.environ, "SYSTEMD_COLORS": "0", "SYSTEMD_URLIFY": "0"},
    )

    async def pump_logs():
        assert proc.stdout is not None
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            text = strip_ansi(line.decode("utf-8", errors="replace")).rstrip()
            if text:
                await websocket.send_json({"type": "log", "data": text})

    task = asyncio.create_task(pump_logs())
    try:
        while True:
            msg = await websocket.receive_json()
            if msg.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
            elif msg.get("type") == "cmd":
                command = (msg.get("data") or "").strip()
                if not command:
                    continue
                await websocket.send_json({"type": "cmd", "data": f"] {command}"})
                try:
                    rcon = SourceRcon(RCON_HOST, rcon_port(), rcon_password(), timeout=8.0)
                    result = await asyncio.to_thread(rcon.command, command)
                    await websocket.send_json(
                        {"type": "rcon", "data": result or "(ok, pas de réponse)"}
                    )
                except Exception as e:
                    await websocket.send_json({"type": "error", "data": f"RCON: {e}"})
    except WebSocketDisconnect:
        pass
    finally:
        srv.reset_current(token)
        task.cancel()
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


if __name__ == "__main__":
    import uvicorn

    port = int(ENV.get("PANEL_PORT", "8080"))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)
