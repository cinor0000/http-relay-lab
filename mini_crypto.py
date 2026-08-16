"""
קריפטוגרפיה מינימלית לערוץ מוצפן — פייתון טהור, בלי ספריות חיצוניות.
בדיוק אותן פרימיטיבות ש-WireGuard משתמש בהן:

    X25519    - החלפת מפתחות (Diffie-Hellman על עקום אליפטי)
    ChaCha20  - הצפנת זרם
    HMAC-SHA256 - אימות (במקום Poly1305, כדי להישאר עם ספריית התקן)
    HKDF      - גזירת מפתחות

בקוד אמיתי משתמשים בספריית crypto בדוקה (cryptography / libsodium).
כאן הכל כתוב במפורש כדי שיהיה אפשר לראות מה באמת קורה.
"""

import hashlib
import hmac
import os
import struct

# ---------------------------------------------------------------- X25519
# RFC 7748 - סולם מונטגומרי על העקום Curve25519

_P = 2 ** 255 - 19
_A24 = 121665


def x25519(scalar: bytes, u_coord: bytes) -> bytes:
    """כפל נקודה: מקבל מפתח פרטי (32B) ומפתח ציבורי (32B), מחזיר סוד משותף."""
    k = bytearray(scalar)
    k[0] &= 248            # "clamping" - מנטרל התקפות על תת-חבורות
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    x1 = int.from_bytes(u_coord, "little") % _P

    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        if swap ^ kt:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt

        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = pow(da + cb, 2, _P)
        z3 = x1 * pow(da - cb, 2, _P) % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


_BASE_POINT = (9).to_bytes(32, "little")


def generate_keypair():
    """זוג מפתחות אפמרלי — נוצר מחדש בכל חיבור (Perfect Forward Secrecy)."""
    private = os.urandom(32)
    public = x25519(private, _BASE_POINT)
    return private, public


# -------------------------------------------------------------- ChaCha20
# RFC 8439

def _rotl32(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _quarter_round(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 7)


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key))
    state += [counter]
    state += list(struct.unpack("<3I", nonce))

    ws = state[:]
    for _ in range(10):                       # 20 סבבים = 10 כפולים
        _quarter_round(ws, 0, 4, 8, 12)
        _quarter_round(ws, 1, 5, 9, 13)
        _quarter_round(ws, 2, 6, 10, 14)
        _quarter_round(ws, 3, 7, 11, 15)
        _quarter_round(ws, 0, 5, 10, 15)
        _quarter_round(ws, 1, 6, 11, 12)
        _quarter_round(ws, 2, 7, 8, 13)
        _quarter_round(ws, 3, 4, 9, 14)
    return struct.pack("<16I", *[(ws[i] + state[i]) & 0xFFFFFFFF for i in range(16)])


def chacha20(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """הצפנה = XOR עם זרם מפתח. אותה פונקציה בדיוק גם מפענחת."""
    if not data:
        return b""
    n_blocks = (len(data) + 63) // 64
    stream = b"".join(_chacha20_block(key, 1 + i, nonce) for i in range(n_blocks))
    # XOR של המספר השלם כולו בבת אחת - הרבה יותר מהיר מלולאה על בייטים
    mixed = int.from_bytes(data, "big") ^ int.from_bytes(stream[:len(data)], "big")
    return mixed.to_bytes(len(data), "big")


# ------------------------------------------------------------- Poly1305
# RFC 8439 סעיף 2.5 - פונקציית אימות חד-פעמית. הרבה יותר מהירה מ-HMAC
# בקוד מקומפל, ובעיקר: היא מה שתקן ChaCha20-Poly1305 באמת מגדיר.

_POLY_P = (1 << 130) - 5
_POLY_CLAMP = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF


def poly1305(key: bytes, msg: bytes) -> bytes:
    """key הוא מפתח חד-פעמי (32B) — אסור בתכלית האיסור לחזור עליו."""
    r = int.from_bytes(key[:16], "little") & _POLY_CLAMP
    s = int.from_bytes(key[16:32], "little")
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        acc = ((acc + int.from_bytes(block + b"\x01", "little")) * r) % _POLY_P
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    return b"\x00" * ((16 - len(data) % 16) % 16)


def chacha20_poly1305_seal(key, nonce, plaintext, aad=b""):
    """
    הצפנה מאומתת (AEAD) לפי RFC 8439 סעיף 2.8.

    מה שהשתנה לעומת encrypt-then-HMAC שהיה כאן קודם:
    מפתח האימות נגזר מבלוק 0 של ChaCha20 עם אותו nonce, כלומר הוא
    חד-פעמי לכל הודעה — וזה בדיוק מה ש-Poly1305 דורש.

    ה-aad ("נתונים נלווים") מאומת אך לא מוצפן: כאן נכנסת כותרת המסגרת,
    כדי שתוקף לא יוכל לשנות אורך או epoch בלי שנשים לב.
    """
    onetime_key = _chacha20_block(key, 0, nonce)[:32]
    ciphertext = chacha20(key, nonce, plaintext)      # הזרם מתחיל בבלוק 1
    tag = poly1305(onetime_key, aad + _pad16(aad) + ciphertext + _pad16(ciphertext) +
                   struct.pack("<QQ", len(aad), len(ciphertext)))
    return ciphertext, tag


def chacha20_poly1305_open(key, nonce, ciphertext, tag, aad=b""):
    """מחזיר את הטקסט הגלוי, או None אם האימות נכשל."""
    onetime_key = _chacha20_block(key, 0, nonce)[:32]
    expected = poly1305(onetime_key, aad + _pad16(aad) + ciphertext + _pad16(ciphertext) +
                        struct.pack("<QQ", len(aad), len(ciphertext)))
    if not hmac.compare_digest(expected, tag):
        return None
    return chacha20(key, nonce, ciphertext)


# -------------------------------------------------------- זרם מהיר חלופי

def shake_stream(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """
    אותו רעיון בדיוק כמו ChaCha20 - XOR עם זרם מפתח - אבל הזרם מיוצר
    ע"י SHAKE256, שרץ בתוך hashlib בקוד C ולכן מהיר פי כמה מאות
    ממימוש פייתון טהור. SHAKE הוא XOF תקני (FIPS 202), כלומר ייצור זרם
    באורך חופשי הוא בדיוק השימוש שהוא נועד לו.

    ChaCha20 נשאר ברירת המחדל להדגמה כי רואים בו את כל המכניקה;
    את הזרם הזה מפעילים כשצריך תעבורה אמיתית במהירות סבירה.
    """
    if not data:
        return b""
    keystream = hashlib.shake_256(b"stream-v1" + key + nonce).digest(len(data))
    return (int.from_bytes(data, "big") ^
            int.from_bytes(keystream, "big")).to_bytes(len(data), "big")


CIPHERS = {"chacha20": chacha20, "shake256": shake_stream}


# ------------------------------------------------------------ HKDF / MAC

def hkdf(secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """גוזר מפתחות נפרדים מהסוד המשותף (RFC 5869)."""
    prk = hmac.new(salt, secret, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def mac(key: bytes, data: bytes) -> bytes:
    """תג אימות 16 בייט. בלעדיו אפשר לשנות תעבורה מוצפנת בלי שנדע."""
    return hmac.new(key, data, hashlib.sha256).digest()[:16]


def mac_verify(key: bytes, data: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(mac(key, data), tag)   # השוואה בזמן קבוע


if __name__ == "__main__":
    # בדיקת שפיות: שני צדדים מגיעים לאותו סוד משותף
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    assert x25519(a_priv, b_pub) == x25519(b_priv, a_pub)
    print("X25519  ok  ->", x25519(a_priv, b_pub).hex()[:32], "...")

    # וקטור בדיקה רשמי מ-RFC 8439 (סעיף 2.4.2)
    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    plain = b"Ladies and Gentlemen of the class of '99: If I could offer you " \
            b"only one tip for the future, sunscreen would be it."
    expect = "6e2e359a2568f98041ba0728dd0d6981"
    got = chacha20(key, nonce, plain).hex()[:32]
    assert got == expect, (got, expect)
    print("ChaCha20 ok ->", got, "(תואם לוקטור הבדיקה של RFC 8439)")
