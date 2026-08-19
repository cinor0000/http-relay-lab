"""
שכבת ההעברה — על מה המנהרה רוכבת.

עד כאן המנהרה רצה על TCP גולמי. זה מצוין כשיש לך שרת עם IP ופורט פתוח,
אבל רוב האחסון החינמי בענן חושף רק HTTPS על פורט 443. הפתרון המקובל
(‏v2ray/Xray עושים בדיוק את זה) הוא להריץ את המנהרה בתוך WebSocket:
מבחוץ זו סתם בקשת HTTPS רגילה שעברה שדרוג לחיבור דו-כיווני.

שני מימושים לאותו ממשק:
    TcpTransport - הקו הישיר
    WsTransport  - אותו דבר, עטוף במסגרות WebSocket (RFC 6455)

הצפנת המנהרה שלנו לא משתנה בכלל — היא רצה מעל שניהם.
"""

import base64
import hashlib
import os
import socket
import ssl
import struct
from urllib.parse import urlparse

WS_GUID = b"258EAFA5-E914-47DA-95CA-5AB0DC85B11F"

# כמה שניות להמתין לבייט מהמנהרה לפני שמכריזים שהחיבור מת. שני הצדדים
# שולחים keepalive כל ~25 שניות, אז חיבור חי (גם כשאין תעבורה) מתאפס כל 25;
# חיבור שנותק בשקט (NetFree/devtunnel חצי-פתוח) לא מקבל כלום → timeout →
# הנתיב מתחבר מחדש במקום להישאר "זומבי" שבולע חיבורים ומחזיר אותם באיטיות.
WS_READ_TIMEOUT = 40.0


class TransportError(Exception):
    pass


# ------------------------------------------------------------------- TCP

class TcpTransport:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self._buf = b""

    def sendall(self, data: bytes) -> None:
        self.sock.sendall(data)

    def recv_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.sock.recv(max(n - len(self._buf), 4096))
            if not chunk:
                raise TransportError("החיבור נסגר")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ------------------------------------------------------------- WebSocket

def _mask(payload: bytes, key: bytes) -> bytes:
    """XOR עם מפתח מסכה של 4 בייטים — בבת אחת, לא בלולאה."""
    if not payload:
        return payload
    repeats = key * (len(payload) // 4 + 1)
    return (int.from_bytes(payload, "big") ^
            int.from_bytes(repeats[:len(payload)], "big")).to_bytes(len(payload), "big")


class WsTransport:
    """
    מסגור WebSocket בינארי. הלקוח חייב למסך את מה שהוא שולח (כך התקן דורש),
    השרת אסור לו — זה ההבדל היחיד בין שני הצדדים.
    """

    def __init__(self, sock, is_client: bool):
        self.sock = sock
        self.is_client = is_client
        self._raw = b""        # בייטים שהגיעו מהרשת וטרם פורקו למסגרות
        self._buf = b""        # מטען שכבר פורק ומחכה ל-recv_exact

    # --- קריאה גולמית מהסוקט
    def _raw_exact(self, n: int) -> bytes:
        while len(self._raw) < n:
            try:
                chunk = self.sock.recv(max(n - len(self._raw), 8192))
            except socket.timeout:
                raise TransportError("אין תגובה מהמנהרה — חיבור מת")
            if not chunk:
                raise TransportError("החיבור נסגר")
            self._raw += chunk
        out, self._raw = self._raw[:n], self._raw[n:]
        return out

    # --- מסגרת אחת
    def _send_frame(self, payload: bytes, opcode: int = 0x2):
        header = bytearray([0x80 | opcode])          # FIN + סוג המסגרת
        length = len(payload)
        flag = 0x80 if self.is_client else 0x00      # ביט המסכה
        if length < 126:
            header.append(flag | length)
        elif length < 65536:
            header.append(flag | 126)
            header += struct.pack("!H", length)
        else:
            header.append(flag | 127)
            header += struct.pack("!Q", length)
        if self.is_client:
            key = os.urandom(4)
            header += key
            payload = _mask(payload, key)
        self.sock.sendall(bytes(header) + payload)

    def _read_frame(self):
        b0, b1 = self._raw_exact(2)
        opcode = b0 & 0x0F
        masked = b1 & 0x80
        length = b1 & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._raw_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._raw_exact(8))[0]
        key = self._raw_exact(4) if masked else None
        payload = self._raw_exact(length) if length else b""
        if key:
            payload = _mask(payload, key)
        return opcode, payload

    # --- הממשק שהמנהרה משתמשת בו
    def sendall(self, data: bytes) -> None:
        self._send_frame(data)

    def recv_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            opcode, payload = self._read_frame()
            if opcode in (0x0, 0x1, 0x2):            # המשך / טקסט / בינארי
                self._buf += payload
            elif opcode == 0x8:                      # סגירה
                raise TransportError("הצד השני סגר את ה-WebSocket")
            elif opcode == 0x9:                      # ping -> pong
                self._send_frame(payload, opcode=0xA)
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def close(self):
        try:
            self._send_frame(b"", opcode=0x8)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


# ------------------------------------------------ יצירת חיבור מצד הלקוח

def connect(url: str, timeout: float = 20.0, cafile: str = None):
    """
    מקבל כתובת ומחזיר טרנספורט מוכן:
        tcp://host:port      - קו ישיר
        ws://host:port/path  - ‏WebSocket רגיל
        wss://host/path      - ‏WebSocket מוצפן ב-TLS (זה מה שעובר בכל רשת)
    """
    if "://" not in url:
        url = "tcp://" + url
    parsed = urlparse(url)
    scheme = parsed.scheme

    if scheme in ("http", "https"):
        from http_transport import HttpTransport      # long-poll HTTP, לענן
        return HttpTransport(url, cafile=cafile)

    default_port = {"tcp": 9000, "ws": 80, "wss": 443}[scheme]
    host, port = parsed.hostname, parsed.port or default_port

    sock = socket.create_connection((host, port), timeout=timeout)
    if scheme == "wss":
        ctx = ssl.create_default_context(cafile=cafile)
        sock = ctx.wrap_socket(sock, server_hostname=host)
    if scheme == "tcp":
        sock.settimeout(None)
        return TcpTransport(sock)

    path = parsed.path or "/"
    key = base64.b64encode(os.urandom(16)).decode()
    request = (f"GET {path} HTTP/1.1\r\n"
               f"Host: {host}\r\n"
               f"Upgrade: websocket\r\n"
               f"Connection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\n"
               f"Sec-WebSocket-Version: 13\r\n"
               f"User-Agent: Mozilla/5.0\r\n\r\n")
    sock.sendall(request.encode())

    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            raise TransportError("השרת ניתק לפני שהשלים לחיצת יד")
        response += chunk
    head, _, rest = response.partition(b"\r\n\r\n")
    if b"101" not in head.split(b"\r\n")[0]:
        raise TransportError(f"שדרוג ל-WebSocket נכשל: {head.splitlines()[0]!r}")

    expected = base64.b64encode(hashlib.sha1(key.encode() + WS_GUID).digest()).decode()
    if expected.lower().encode() not in head.lower():
        raise TransportError("השרת החזיר Sec-WebSocket-Accept שגוי")

    sock.settimeout(WS_READ_TIMEOUT)          # לזהות חיבור מת (ראה WS_READ_TIMEOUT)
    transport = WsTransport(sock, is_client=True)
    transport._raw = rest                     # מה שכבר הגיע אחרי הכותרות
    return transport


# ------------------------------------------------- קבלת חיבור בצד השרת

def accept_ws(sock: socket.socket):
    """
    מקבל סוקט שהתחבר, קורא את בקשת ה-HTTP, ומשדרג ל-WebSocket.
    בקשה רגילה שאינה שדרוג מקבלת 200 קצר — כך שגם בדיקת בריאות של
    שירות האחסון תעבור, ומי שיפתח את הכתובת בדפדפן לא יראה כלום מעניין.
    """
    request = b""
    while b"\r\n\r\n" not in request:
        chunk = sock.recv(4096)
        if not chunk:
            raise TransportError("החיבור נסגר לפני הבקשה")
        request += chunk
    head, _, rest = request.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        headers[name.strip().lower()] = value.strip()

    if headers.get(b"upgrade", b"").lower() != b"websocket":
        sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                     b"Content-Type: text/plain\r\n\r\nok")
        sock.close()
        return None

    key = headers.get(b"sec-websocket-key", b"")
    accept = base64.b64encode(hashlib.sha1(key + WS_GUID).digest()).decode()
    sock.sendall(("HTTP/1.1 101 Switching Protocols\r\n"
                  "Upgrade: websocket\r\n"
                  "Connection: Upgrade\r\n"
                  f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())
    transport = WsTransport(sock, is_client=False)
    transport._raw = rest
    return transport
