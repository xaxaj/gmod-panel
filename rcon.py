"""Client RCON Source Engine (minimal)."""
from __future__ import annotations

import socket
import struct
import time


SERVERDATA_AUTH = 3
SERVERDATA_AUTH_RESPONSE = 2
SERVERDATA_EXECCOMMAND = 2
SERVERDATA_RESPONSE_VALUE = 0


class RconError(Exception):
    pass


class SourceRcon:
    def __init__(self, host: str, port: int, password: str, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self._req_id = int(time.time()) % 100000

    def _next_id(self) -> int:
        self._req_id += 1
        return self._req_id

    def _pack(self, req_id: int, req_type: int, body: str) -> bytes:
        payload = struct.pack("<ii", req_id, req_type) + body.encode("utf-8") + b"\x00\x00"
        return struct.pack("<i", len(payload)) + payload

    def _recv_packet(self, sock: socket.socket) -> tuple[int, int, str]:
        size_data = self._recv_exact(sock, 4)
        (size,) = struct.unpack("<i", size_data)
        if size < 10 or size > 4096:
            raise RconError(f"Taille paquet RCON invalide: {size}")
        data = self._recv_exact(sock, size)
        req_id, req_type = struct.unpack("<ii", data[:8])
        body = data[8:-2].decode("utf-8", errors="replace")
        return req_id, req_type, body

    def _recv_exact(self, sock: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise RconError("Connexion RCON fermée")
            buf += chunk
        return buf

    def command(self, cmd: str) -> str:
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            sock.settimeout(self.timeout)
            auth_id = self._next_id()
            sock.sendall(self._pack(auth_id, SERVERDATA_AUTH, self.password))

            # Certains serveurs envoient RESPONSE_VALUE puis AUTH_RESPONSE
            authenticated = False
            for _ in range(3):
                rid, rtype, _body = self._recv_packet(sock)
                if rid == -1:
                    raise RconError("Authentification RCON refusée")
                if rtype == SERVERDATA_AUTH_RESPONSE and rid == auth_id:
                    authenticated = True
                    break
                if rtype == SERVERDATA_AUTH_RESPONSE:
                    authenticated = True
                    break
            if not authenticated:
                raise RconError("Pas de réponse AUTH RCON")

            cmd_id = self._next_id()
            sock.sendall(self._pack(cmd_id, SERVERDATA_EXECCOMMAND, cmd))
            end_id = self._next_id()
            sock.sendall(self._pack(end_id, SERVERDATA_RESPONSE_VALUE, ""))

            parts: list[str] = []
            deadline = time.time() + self.timeout
            while time.time() < deadline:
                sock.settimeout(max(0.2, deadline - time.time()))
                try:
                    rid, rtype, body = self._recv_packet(sock)
                except (socket.timeout, TimeoutError):
                    break
                if rid == end_id:
                    # sometimes followed by empty packet; stop after seeing end marker
                    break
                if rid == cmd_id and rtype == SERVERDATA_RESPONSE_VALUE:
                    parts.append(body)
                elif rtype == SERVERDATA_RESPONSE_VALUE and rid != end_id:
                    parts.append(body)
            return "".join(parts).strip()
