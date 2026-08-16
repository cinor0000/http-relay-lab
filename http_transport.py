# -*- coding: utf-8 -*-
"""
Transport she-rochev al bakashot HTTP regilot (lo WebSocket).

Lama: mul harbe shirutei tunnel/proxy, shidrug WebSocket mekabel 500,
aval GET/POST regilim overim mizui. Az kan ha-minhara
metuksheret ke-selsela shel bakashot HTTP:

    POST /u/<sid>   -- ha-lakoach sholeach batim la-server (uplink)
    GET  /d/<sid>   -- long-poll: ha-server mahzir batim la-lakoach (downlink)
    POST /c/<sid>   -- sgira

Kol batim she-overim kvar mutzpanim v-me'umatim al-yedei shchavat
ha-protocol (protocol.py) -- ha-HTTP hu rak ha-tzinor. Cloudflare ro'e
rak bakashot HTTPS regilot le-domain ehad.
"""

import http.client
import http.server
import os
import ssl
import struct
import threading
import time
import urllib.parse

from reliable import ClosedError, ReliableStream
from transport import TransportError

POLL_HOLD = 20.0            # kama shniyot ha-server mahzik long-poll patuach
IDLE_LIMIT = 120.0         # sgirat session she-ne'elam
NUM_POLLS = 4              # kama lulaot mkabilot (marhiv et ha-tzinor)
SERVER_HOLD = 2.0          # long-poll: kama ha-server mehake le-mida lifney tshuva


# =================================================================
#  Tzad ha-lakoach
# =================================================================

class HttpTransport:
    """
    זרם בייטים דו-כיווני אמין מעל בקשות HTTP. תואם ל-ProtocolChannel.

    כל הבייטים עוברים דרך ReliableStream (מספרי סידור, אישורים, שידור חוזר),
    ולכן איבוד תשובת HTTP בודדת **לא** יוצר חור בזרם — היא פשוט תשודר שוב.
    מספר לולאות מקבילות, כל אחת על חיבור מתמשך, מזרימות את המנות אל
    נקודת הקצה האחת /t/<sid>. שכבת ההצפנה מעל לא רואה מזה כלום.
    """

    def __init__(self, url, cafile=None):
        parts = urllib.parse.urlparse(url)
        self.host = parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.https = parts.scheme == "https"
        self.sid = os.urandom(8).hex()
        self._ctx = ssl.create_default_context(cafile=cafile) if self.https else None

        self._rs = ReliableStream()
        self._alive = True
        self._conns = {}                             # slot -> HTTP(S)Connection
        for i in range(NUM_POLLS):
            threading.Thread(target=self._pump_loop, args=(f"t{i}",),
                             daemon=True).start()

    def _conn(self):
        if self.https:
            return http.client.HTTPSConnection(self.host, self.port,
                                               context=self._ctx, timeout=60)
        return http.client.HTTPConnection(self.host, self.port, timeout=60)

    def _post(self, slot, path, body):
        """בקשה על חיבור מתמשך ייעודי לחריץ. אם נפל — פותח חדש ומנסה שוב."""
        headers = {"User-Agent": "Mozilla/5.0",
                   "Content-Type": "application/octet-stream",
                   "Content-Length": str(len(body)),
                   "Connection": "keep-alive"}
        for attempt in (1, 2):
            conn = self._conns.get(slot)
            if conn is None:
                conn = self._conn()
                self._conns[slot] = conn
            try:
                conn.request("POST", path, body=body, headers=headers)
                resp = conn.getresponse()
                data = resp.read()
                if resp.status >= 500:
                    raise TransportError(f"HTTP {resp.status}")
                return data
            except (OSError, http.client.HTTPException, TransportError):
                try:
                    conn.close()
                except OSError:
                    pass
                self._conns[slot] = None
                if attempt == 2 or not self._alive:
                    raise
        return b""

    def _pump_loop(self, slot):
        """
        בונה מנה מ-ReliableStream, שולח, מזין את התשובה חזרה אליו — בלולאה
        צמודה. אין כאן ויסות מלאכותי: השרת מחזיק את התשובה (long-poll) עד
        שיש מידע להוריד או עד SERVER_HOLD, ולכן הלולאה לא מסתובבת סתם, וגם
        לא מפספסת מידע להורדה. זה מה שמשמר את המהירות.
        """
        while self._alive:
            msg = self._rs.build()
            try:
                resp = self._post(slot, f"/t/{self.sid}", msg)
            except (OSError, TransportError, http.client.HTTPException):
                if not self._alive:
                    return
                time.sleep(0.3)
                continue
            if resp:
                self._rs.parse(resp)

    def sendall(self, data):
        self._rs.send(data)

    def recv_exact(self, n):
        try:
            return self._rs.recv_exact(n)
        except ClosedError:
            raise TransportError("ha-hibur nisgar")

    def close(self):
        self._alive = False
        self._rs.close()
        try:
            conn = self._conn()
            conn.request("POST", f"/c/{self.sid}", body=b"",
                         headers={"Content-Length": "0"})
            conn.getresponse().read()
            conn.close()
        except (OSError, TransportError, http.client.HTTPException):
            pass
        for conn in list(self._conns.values()):
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass


# =================================================================
#  Tzad ha-server: gesher batim bli socket
# =================================================================

class ByteBridge:
    """Mesamen la-protocol ke-socket, aval nizon me-bakashot HTTP."""

    def __init__(self):
        self._rs = ReliableStream()
        self.alive = True
        self.last_seen = time.time()

    # -- ממשק לשכבת ההצפנה (protocol.py) — נראה כמו socket --
    def recv_exact(self, n):
        try:
            return self._rs.recv_exact(n)
        except ClosedError:
            raise TransportError("ha-hibur nisgar")

    def sendall(self, data):
        self._rs.send(data)

    # -- ממשק ל-HTTP: מנה נכנסת -> מנה יוצאת (עם long-poll) --
    def exchange(self, body):
        self.last_seen = time.time()
        if body:
            self._rs.parse(body)
        # long-poll: ממתין עד שיש מידע לשלוח, כדי לא להסתובב סתם
        if not self._rs.has_output():
            self._rs.wait_output(SERVER_HOLD)
        return self._rs.build()

    def close(self):
        self.alive = False
        self._rs.close()


def serve_http(host, port, start_session, log=print):
    """
    Marim server HTTP. `start_session(bridge)` yikra pa'am le-chol session
    hadash -- hu ahra'i le-hafeil et lachitzat ha-yad ve-lulaat ha-session
    me'al ha-bridge (be-thread nifrad).
    """
    sessions = {}
    lock = threading.Lock()

    def get_bridge(sid, create):
        with lock:
            bridge = sessions.get(sid)
            if bridge is None and create:
                bridge = ByteBridge()
                sessions[sid] = bridge
                threading.Thread(target=_run, args=(sid, bridge), daemon=True).start()
            return bridge

    def _run(sid, bridge):
        try:
            start_session(bridge)
        except Exception as exc:                     # noqa: BLE001
            log(f"session {sid[:6]}: {exc}")
        finally:
            bridge.close()
            with lock:
                sessions.pop(sid, None)

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _reply(self, code, body=b""):
            self.send_response(code)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_GET(self):
            self._reply(200, b"ok")                  # bdikat bri'ut / dapdefan

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            if self.path.startswith("/t/"):          # transport: mana nichneset -> yotzet
                bridge = get_bridge(self.path[3:], create=True)
                try:
                    self._reply(200, bridge.exchange(body))
                except (OSError, TransportError):
                    self._reply(200, b"")
            elif self.path.startswith("/c/"):
                bridge = get_bridge(self.path[3:], create=False)
                if bridge:
                    bridge.close()
                self._reply(200)
            else:
                self._reply(404)

    server = http.server.ThreadingHTTPServer((host, port), Handler)
    log(f"HTTP transport mby'azin al {host}:{port}")

    def reaper():                                    # menake sessions ne'elamim
        while True:
            time.sleep(30)
            now = time.time()
            with lock:
                dead = [s for s, b in sessions.items() if now - b.last_seen > IDLE_LIMIT]
                for s in dead:
                    sessions[s].close()
                    sessions.pop(s, None)

    threading.Thread(target=reaper, daemon=True).start()
    server.serve_forever()
