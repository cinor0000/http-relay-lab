"""
ריבוב זרמים — כל החיבורים חולקים מנהרה אחת.

בגרסה הראשונה כל חיבור של הדפדפן פתח מנהרה משלו, ועשה לחיצת יד שלמה
(‏X25519 בפייתון טהור = בערך עשירית שנייה) לפני שהעביר בייט אחד. דף
אינטרנט טיפוסי פותח עשרות חיבורים, וזה נהיה החלק היקר ביותר.

כאן יש מנהרה אחת מתמשכת, ובתוכה זרמים ממוספרים:

    [סוג 1B][מספר זרם 4B][מטען]

    OPEN     - "פתח לי חיבור אל host:port"
    OPEN_OK  - היעד ענה, אפשר להתחיל
    DATA     - בייטים של הזרם הזה
    EOF      - סיימתי לשדר (הצד השני עדיין יכול)
    CLOSE    - הזרם נסגר

כך חיבור חדש עולה הודעה אחת קטנה במקום לחיצת יד שלמה.

הערה על בקרת זרימה: לכל זרם יש תור עם גבול. אם צד אחד קורא לאט,
התור מתמלא והקורא הראשי ממתין — כלומר זרם איטי אחד יכול להאט את השאר.
מימוש בוגר פותר את זה עם חלונות לכל זרם; כאן נשאר הגבול הפשוט.
"""

import queue
import socket
import struct
import threading

from protocol import ProtocolError
from transport import TransportError

MSG_OPEN, MSG_OPEN_OK, MSG_OPEN_FAIL, MSG_DATA, MSG_EOF, MSG_CLOSE = range(1, 7)
CHUNK = 16384
QUEUE_LIMIT = 64

# סמנים בתור ה-writer. חשוב שהסגירה תעבור דרך התור ולא תסגור את הסוקט
# ישירות — אחרת סגירה מרוץ עם ה-writer מוחקת נתונים שעדיין בתור (עד 1MB).
_EOF = object()      # הצד המרוחק סיים לשדר — לסגור כתיבה אחרי ריקון
_CLOSE = object()    # הזרם נסגר לגמרי — לסגור את הסוקט אחרי ריקון


class Stream:
    def __init__(self, session, sid, sock=None):
        self.session = session
        self.sid = sid
        self.sock = sock
        self.inbox = queue.Queue(maxsize=QUEUE_LIMIT)
        self.ready = threading.Event()
        self.accepted = False
        self._closed = False

    # --- מהמנהרה אל הסוקט המקומי
    def _writer(self):
        """
        מרוקן את התור אל הסוקט. הסוקט נסגר **רק כאן**, אחרי שכל הנתונים
        שבתור נכתבו — כדי שסגירת הזרם לא תמחק את הזנב שעדיין ממתין.
        """
        try:
            while True:
                item = self.inbox.get()
                if item is _EOF or item is None:   # הצד המרוחק סיים לשדר
                    try:
                        self.sock.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue                       # ממשיכים עד CLOSE
                if item is _CLOSE:
                    break                          # רוקנּו הכל — עכשיו סוגרים
                self.sock.sendall(item)
        except OSError:
            pass
        finally:
            try:
                self.sock.close()
            except (OSError, AttributeError):
                pass

    # --- מהסוקט המקומי אל המנהרה
    def _reader(self):
        try:
            while True:
                data = self.sock.recv(CHUNK)
                if not data:
                    self.session.send_msg(MSG_EOF, self.sid)
                    return
                self.session.send_msg(MSG_DATA, self.sid, data)
        except OSError:
            pass
        finally:
            self.session.send_msg(MSG_CLOSE, self.sid)
            self.session.drop(self.sid)

    def start(self):
        threading.Thread(target=self._writer, daemon=True).start()
        threading.Thread(target=self._reader, daemon=True).start()

    def close(self):
        if self._closed:
            return
        self._closed = True
        # מעבירים את הסגירה דרך התור, כדי שה-writer יסגור את הסוקט רק
        # אחרי שרוקן את כל מה שנשאר. put חוסם (עם גבול) כדי לשמור על הסדר.
        if self.sock is not None:
            try:
                self.inbox.put(_CLOSE, timeout=30)
                return
            except queue.Full:
                pass                               # ה-writer תקוע — סוגרים בכוח
        try:
            self.sock.close()
        except (OSError, AttributeError):
            pass


class Session:
    """
    צד אחד של מנהרה מרובבת. `on_open` קיים רק בשרת: הוא מקבל
    (stream, "host:port") ואחראי לחבר את הזרם ליעד האמיתי.
    """

    def __init__(self, chan, on_open=None, log=print):
        self.chan = chan
        self.on_open = on_open
        self.log = log
        self.streams = {}
        self.lock = threading.Lock()
        self._next_id = 1
        self.alive = True

    # ------------------------------------------------------- שליחה

    def send_msg(self, msg, sid, payload=b""):
        if not self.alive:
            return
        try:
            for offset in range(0, max(len(payload), 1), 15000):
                self.chan.send(bytes([msg]) + struct.pack("!I", sid) +
                               payload[offset:offset + 15000])
        except (ProtocolError, TransportError, OSError):
            self.shutdown()

    def new_stream(self, sock, target: str) -> Stream:
        """צד הלקוח: מקצה מספר זרם ומבקש מהשרת לפתוח חיבור."""
        with self.lock:
            sid = self._next_id
            self._next_id += 1
            stream = Stream(self, sid, sock)
            self.streams[sid] = stream
        self.send_msg(MSG_OPEN, sid, target.encode())
        return stream

    def drop(self, sid):
        with self.lock:
            stream = self.streams.pop(sid, None)
        if stream:
            stream.close()

    # ------------------------------------------------------- קבלה

    def run(self):
        """הלולאה הראשית — קוראת מהמנהרה ומנתבת לזרמים."""
        try:
            while True:
                frame = self.chan.recv()
                if len(frame) < 5:
                    continue
                msg = frame[0]
                sid = struct.unpack("!I", frame[1:5])[0]
                payload = frame[5:]

                if msg == MSG_DATA:
                    stream = self.streams.get(sid)
                    if stream:
                        stream.inbox.put(payload)
                elif msg == MSG_OPEN:
                    self._accept(sid, payload.decode("utf-8", "replace"))
                elif msg == MSG_OPEN_OK:
                    stream = self.streams.get(sid)
                    if stream:
                        stream.accepted = True
                        stream.ready.set()
                elif msg == MSG_OPEN_FAIL:
                    stream = self.streams.get(sid)
                    if stream:
                        stream.ready.set()
                elif msg == MSG_EOF:
                    stream = self.streams.get(sid)
                    if stream:
                        stream.inbox.put(_EOF)
                elif msg == MSG_CLOSE:
                    self.drop(sid)
        except (ProtocolError, TransportError, OSError) as exc:
            self.log(f"המנהרה נסגרה: {exc}")
        finally:
            self.shutdown()

    def _accept(self, sid, target):
        if not self.on_open:
            return
        stream = Stream(self, sid)
        with self.lock:
            self.streams[sid] = stream
        threading.Thread(target=self.on_open, args=(stream, target), daemon=True).start()

    def shutdown(self):
        if not self.alive:
            return
        self.alive = False
        with self.lock:
            streams, self.streams = list(self.streams.values()), {}
        for stream in streams:
            stream.close()
        self.chan.close()

    def keepalive_loop(self, seconds=25):
        """שומר על החיבור פתוח מול נתבים ושירותי ענן שמנתקים חיבור שקט."""
        while self.alive:
            for _ in range(seconds * 4):
                if not self.alive:
                    return
                threading.Event().wait(0.25)
            try:
                self.chan.send_keepalive()
            except (ProtocolError, TransportError, OSError):
                return
