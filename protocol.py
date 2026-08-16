"""
שכבת ההצפנה של המנהרה: לחיצת יד, מסגרות מאומתות, והחלפת מפתחות תוך כדי ריצה.

מבנה מסגרת על הקו:

    +---------+---------+---------------------------+----------+
    | אורך 2B | epoch 1B|        טקסט מוצפן          | תג 16B   |
    +---------+---------+---------------------------+----------+
      \_______________/
        מאומת אך גלוי (AAD) — תוקף לא יכול לשנות אורך או epoch

הטקסט הגלוי שבפנים בנוי כך:

    [סוג 1B][אורך אמיתי 2B][מטען][ריפוד]

הריפוד קיים כדי שאורך המסגרת על הקו לא יסגיר את אורך המידע האמיתי.

ה-nonce לא נשלח: כל צד סופר מסגרות בעצמו, והמונה מתאפס בכל epoch.
מסגרת משוחזרת ("replay") או מסגרת שהוזזה בסדר — ייכשלו באימות.

**החלפת מפתחות תוך כדי ריצה (rekey):** כל כמה דקות או כל כמה מגה-בייטים,
הלקוח מתחיל סבב Diffie-Hellman חדש בתוך המנהרה הקיימת. ה-epoch שבכותרת
הוא מה שמאפשר לצד השני לדעת באיזה מפתח לפענח בזמן המעבר, בלי לאבד
אפילו מסגרת אחת. הסוד החדש מעורבב בסוד הישן, כך שהחלפה לא יכולה להחליש.
"""

import os
import struct
import threading
import time

from mini_crypto import (chacha20_poly1305_open, chacha20_poly1305_seal, generate_keypair,
                         hkdf, mac, mac_verify, shake_stream, x25519)
from transport import TransportError

MAX_PAYLOAD = 16384
TAG_LEN = 16
PAD_TO = 64                      # אורכי מסגרות מעוגלים לכפולה של 64

FRAME_DATA = 0
FRAME_REKEY_INIT = 1
FRAME_REKEY_ACK = 2
FRAME_PADDING = 3
FRAME_KEEPALIVE = 4

REKEY_AFTER_BYTES = 64 * 1024 * 1024
REKEY_AFTER_SECONDS = 300


class ProtocolError(Exception):
    pass


# ------------------------------------------------------- ערכות הצפנה

def _seal_chacha(key, nonce, plaintext, aad):
    return chacha20_poly1305_seal(key[:32], nonce, plaintext, aad)


def _open_chacha(key, nonce, ciphertext, tag, aad):
    return chacha20_poly1305_open(key[:32], nonce, ciphertext, tag, aad)


def _seal_shake(key, nonce, plaintext, aad):
    ciphertext = shake_stream(key[:32], nonce, plaintext)
    return ciphertext, mac(key[32:], aad + nonce + ciphertext)


def _open_shake(key, nonce, ciphertext, tag, aad):
    if not mac_verify(key[32:], aad + nonce + ciphertext, tag):
        return None
    return shake_stream(key[:32], nonce, ciphertext)


SUITES = {
    # שם הערכה: (איטום, פתיחה) — שני הצדדים חייבים לבחור אותה ערכה
    "chacha20-poly1305": (_seal_chacha, _open_chacha),   # התקן, פייתון טהור, איטי
    "shake256-hmac": (_seal_shake, _open_shake),         # רץ ב-C, מהיר, לגלישה
}


class SecureChannel:
    def __init__(self, transport, suite, initiator, root, send_key, recv_key):
        self.transport = transport
        self.suite = suite
        self._seal, self._open = SUITES[suite]
        self.initiator = initiator

        self._root = root                     # הסוד שממנו נגזרים המפתחות
        self._epoch = 0
        self._send_keys = {0: send_key}
        self._recv_keys = {0: recv_key}
        self._send_counter = 0
        self._recv_counters = {0: 0}

        self._lock = threading.Lock()
        self._rekey_priv = None
        self._bytes_since_rekey = 0
        self._last_rekey = time.time()
        self.rekeys_done = 0

    # ------------------------------------------------------ שליחה

    @staticmethod
    def _nonce(counter):
        return b"\x00" * 4 + struct.pack("<Q", counter)

    def _send_frame(self, kind, payload):
        if len(payload) > MAX_PAYLOAD:
            raise ProtocolError("מטען ארוך מדי למסגרת אחת")
        body = bytes([kind]) + struct.pack("!H", len(payload)) + payload
        padding = (-len(body)) % PAD_TO
        body += b"\x00" * padding

        with self._lock:
            epoch = self._epoch
            nonce = self._nonce(self._send_counter)
            self._send_counter += 1
            header = struct.pack("!HB", len(body), epoch)
            ciphertext, tag = self._seal(self._send_keys[epoch], nonce, body, header)
            self.transport.sendall(header + ciphertext + tag)
            self._bytes_since_rekey += len(body)

    def send(self, data: bytes) -> None:
        """שולח מטען מהשכבה שמעל, מפוצל למסגרות אם צריך."""
        for offset in range(0, max(len(data), 1), MAX_PAYLOAD):
            self._send_frame(FRAME_DATA, data[offset:offset + MAX_PAYLOAD])
        self._maybe_rekey()

    def send_keepalive(self):
        self._send_frame(FRAME_KEEPALIVE, b"")

    # ------------------------------------------------------ קבלה

    def recv(self) -> bytes:
        """מחזיר את המטען הבא של השכבה שמעל. מסגרות שירות מטופלות בדרך."""
        while True:
            kind, payload = self._recv_frame()
            if kind == FRAME_DATA:
                return payload
            if kind == FRAME_REKEY_INIT:
                self._handle_rekey_init(payload)
            elif kind == FRAME_REKEY_ACK:
                self._handle_rekey_ack(payload)
            # PADDING ו-KEEPALIVE נזרקים בשקט

    def _recv_frame(self):
        header = self.transport.recv_exact(3)
        length, epoch = struct.unpack("!HB", header)
        if length > MAX_PAYLOAD + PAD_TO + 3:
            raise ProtocolError("מסגרת ארוכה מדי")
        ciphertext = self.transport.recv_exact(length)
        tag = self.transport.recv_exact(TAG_LEN)

        key = self._recv_keys.get(epoch)
        if key is None:
            raise ProtocolError(f"מסגרת ב-epoch לא מוכר ({epoch})")
        nonce = self._nonce(self._recv_counters[epoch])
        body = self._open(key, nonce, ciphertext, tag, header)
        if body is None:
            raise ProtocolError("אימות נכשל: סיסמה שגויה, שיבוש או ניסיון זיוף")
        self._recv_counters[epoch] += 1

        if epoch > 0 and (epoch - 1) in self._recv_keys:
            del self._recv_keys[epoch - 1]        # ה-epoch הישן כבר לא נחוץ
            self._recv_counters.pop(epoch - 1, None)

        kind = body[0]
        size = struct.unpack("!H", body[1:3])[0]
        return kind, body[3:3 + size]

    # ------------------------------------------- החלפת מפתחות תקופתית

    def _maybe_rekey(self):
        if not self.initiator or self._rekey_priv is not None:
            return
        if (self._bytes_since_rekey < REKEY_AFTER_BYTES and
                time.time() - self._last_rekey < REKEY_AFTER_SECONDS):
            return
        priv, pub = generate_keypair()
        self._rekey_priv = priv
        self._send_frame(FRAME_REKEY_INIT, pub)

    def force_rekey(self):
        """לשימוש בבדיקות — מתחיל סבב החלפה מיד."""
        if not self.initiator:
            raise ProtocolError("רק היוזם מתחיל החלפת מפתחות")
        priv, pub = generate_keypair()
        self._rekey_priv = priv
        self._send_frame(FRAME_REKEY_INIT, pub)

    def _advance(self, shared, peer_pub, my_pub):
        """גוזר את מפתחות ה-epoch הבא ומעביר אליו את כיוון השליחה."""
        transcript = (peer_pub + my_pub) if self.initiator else (my_pub + peer_pub)
        self._root = hkdf(shared + self._root, transcript, b"rekey root", 32)
        forward = hkdf(self._root, transcript, b"client->server", 64)
        backward = hkdf(self._root, transcript, b"server->client", 64)

        new_epoch = self._epoch + 1
        if self.initiator:
            send_key, recv_key = forward, backward
        else:
            send_key, recv_key = backward, forward

        self._recv_keys[new_epoch] = recv_key
        self._recv_counters[new_epoch] = 0
        with self._lock:
            self._send_keys[new_epoch] = send_key
            self._send_counter = 0
            self._epoch = new_epoch
            self._send_keys.pop(new_epoch - 1, None)
        self._bytes_since_rekey = 0
        self._last_rekey = time.time()
        self.rekeys_done += 1

    def _handle_rekey_init(self, peer_pub):
        priv, pub = generate_keypair()
        self._send_frame(FRAME_REKEY_ACK, pub)      # עדיין ב-epoch הישן
        self._advance(x25519(priv, peer_pub), peer_pub, pub)

    def _handle_rekey_ack(self, peer_pub):
        priv, self._rekey_priv = self._rekey_priv, None
        if priv is None:
            raise ProtocolError("אישור החלפת מפתחות שלא ביקשנו")
        my_pub = x25519(priv, (9).to_bytes(32, "little"))
        self._advance(x25519(priv, peer_pub), peer_pub, my_pub)

    def close(self):
        self.transport.close()


# --------------------------------------------------------- לחיצת יד

_CONFIRM = b"link/2"


def _derive(shared, psk, transcript):
    root = hkdf(shared + psk, transcript, b"root", 32)
    return (root,
            hkdf(root, transcript, b"client->server", 64),
            hkdf(root, transcript, b"server->client", 64))


def client_handshake(transport, psk: bytes, suite: str = "chacha20-poly1305"):
    priv, pub = generate_keypair()
    transport.sendall(pub)
    server_pub = transport.recv_exact(32)

    root, c2s, s2c = _derive(x25519(priv, server_pub), psk, pub + server_pub)
    chan = SecureChannel(transport, suite, True, root, c2s, s2c)

    chan.send(_CONFIRM)
    try:
        confirmed = chan.recv() == _CONFIRM
    except (ProtocolError, TransportError):
        confirmed = False
    if not confirmed:
        raise ProtocolError("השרת דחה את החיבור — סיסמה שגויה או ערכת הצפנה שונה")
    return chan


def server_handshake(transport, psk: bytes, suite: str = "chacha20-poly1305"):
    client_pub = transport.recv_exact(32)
    priv, pub = generate_keypair()
    transport.sendall(pub)

    root, c2s, s2c = _derive(x25519(priv, client_pub), psk, client_pub + pub)
    chan = SecureChannel(transport, suite, False, root, s2c, c2s)

    if chan.recv() != _CONFIRM:
        raise ProtocolError("הלקוח לא אושר")
    chan.send(_CONFIRM)
    return chan
