"""
צד השרת — זה מה שרץ על המכונה המרוחקת.

    python relay_server.py --port 9000                     (TCP ישיר)
    python relay_server.py --transport ws --port 8080      (‏WebSocket, לענן)

במצב WebSocket השרת מדבר HTTP: בקשה רגילה מקבלת "ok" קצר, ורק בקשה עם
Upgrade: websocket הופכת למנהרה. כך אפשר להעמיד אותו מאחורי כל שירות
שמעביר HTTPS בלבד — וזה כמעט כל האחסון החינמי בענן.
"""

import argparse
import socket
import threading

from mux import MSG_OPEN_FAIL, MSG_OPEN_OK, Session
from protocol import ProtocolError, server_handshake
from transport import TcpTransport, TransportError, accept_ws

_print_lock = threading.Lock()


def log(*parts):
    with _print_lock:
        print("[server]", *parts, flush=True)


def connect_target(stream, target: str):
    """נקרא לכל בקשת OPEN: פותח חיבור ליעד ומחבר אותו לזרם."""
    host, _, port = target.rpartition(":")
    try:
        remote = socket.create_connection((host, int(port)), timeout=20)
        remote.settimeout(None)
    except (OSError, ValueError) as exc:
        log(f"זרם {stream.sid}: {target} נכשל ({exc})")
        stream.session.send_msg(MSG_OPEN_FAIL, stream.sid)
        stream.session.drop(stream.sid)
        return
    log(f"זרם {stream.sid} -> {target}")
    stream.sock = remote
    stream.session.send_msg(MSG_OPEN_OK, stream.sid)
    stream.start()


def run_channel(transport, psk, suite):
    """לחיצת יד + לולאת session על טרנספורט מוכן (משותף לכל הטרנספורטים)."""
    chan = server_handshake(transport, psk, suite)
    log(f"מנהרה נפתחה (ערכה: {suite})")
    session = Session(chan, on_open=connect_target, log=log)
    threading.Thread(target=session.keepalive_loop, daemon=True).start()
    session.run()
    log(f"מנהרה נסגרה ({chan.rekeys_done} החלפות מפתחות)")


def handle(sock, addr, psk: bytes, suite: str, use_ws: bool):
    try:
        transport = accept_ws(sock) if use_ws else TcpTransport(sock)
        if transport is None:
            return                                   # בקשת HTTP רגילה, לא מנהרה
        run_channel(transport, psk, suite)
    except (ProtocolError, TransportError, OSError) as exc:
        log("סיום:", exc)
        try:
            sock.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--psk", default="demo-secret")
    ap.add_argument("--transport", default="tcp", choices=["tcp", "ws", "http"])
    ap.add_argument("--suite", default="chacha20-poly1305",
                    choices=["chacha20-poly1305", "shake256-hmac"])
    args = ap.parse_args()
    psk = args.psk.encode()

    if args.transport == "http":
        from http_transport import serve_http         # רוכב על HTTP, עובר Cloudflare
        serve_http(args.host, args.port,
                   lambda bridge: run_channel(bridge, psk, args.suite), log=log)
        return

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen(128)
    log(f"מאזין על {args.host}:{args.port} ({args.transport}, {args.suite})")

    while True:
        sock, addr = listener.accept()
        threading.Thread(target=handle,
                         args=(sock, addr, psk, args.suite, args.transport == "ws"),
                         daemon=True).start()


if __name__ == "__main__":
    main()
