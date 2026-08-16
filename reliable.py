# -*- coding: utf-8 -*-
"""
שכבת אמינות מעל הטרנספורט — הופכת ערוץ מנות שמאבד/מסדר-מחדש לזרם בייטים
רציף, מסודר, ובלי אובדן. כך שכבת ההצפנה הקשוחה (protocol.py) לעולם לא
רואה חור, והמנהרה לא נופלת על מנה בודדת שאבדה.

Selective-repeat ARQ, סימטרי לשני הצדדים:
  * כל צד מספר את הבייטים שהוא שולח: seq = היסט הבייט הראשון במנה.
  * המקבל מאשר באופן **מצטבר**: ack = ההיסט הרציף הבא שהוא מצפה לו.
  * השולח שומר מנות שלא אושרו ומשדר אותן שוב אחרי RTO.
  * המקבל מחזיק מנות שהגיעו מחוץ לסדר, וממזג כשנסגר החור.

הממשק זהה למה ש-protocol.py מצפה לו: send() / recv_exact().
המסגור על החוט (build/parse) נעטף על ידי http_transport.
"""

import struct
import threading
import time

MAX_SEG = 65536             # מקסימום בייטים במנה אחת
WINDOW = 512 * 1024         # כמה בייטים לא-מאושרים מותר שיהיו בדרך בו-זמנית
RTO = 1.5                   # שניות עד שידור חוזר של מנה שלא אושרה
HDR = struct.Struct(">BQQI")   # flags(1) ack(8) seq(8) dlen(4)


class ClosedError(Exception):
    pass


class ReliableStream:
    def __init__(self):
        self.cond = threading.Condition()
        # שליחה
        self.send_buf = bytearray()      # בייטים מ-send_base והלאה, שטרם אושרו
        self.send_base = 0               # ההיסט של send_buf[0]
        self.send_ptr = 0                # ההיסט הבא שנשלח בפעם הראשונה
        self.inflight = {}               # off -> [length, sent_time]
        # קבלה
        self.recv_next = 0               # ההיסט הרציף הבא שאנחנו מצפים לו
        self.recv_ready = bytearray()    # בייטים מסודרים שמחכים לקריאה
        self.recv_hold = {}              # seq -> bytes (הגיעו מחוץ לסדר)
        self.closed = False

    # ------------------------------------------------ ממשק לשכבת האפליקציה

    def send(self, data):
        with self.cond:
            self.send_buf += data
            self.cond.notify_all()

    def recv_exact(self, n):
        with self.cond:
            while len(self.recv_ready) < n:
                if self.closed:
                    raise ClosedError("הזרם נסגר")
                self.cond.wait(1.0)
            out = bytes(self.recv_ready[:n])
            del self.recv_ready[:n]
            return out

    def close(self):
        with self.cond:
            self.closed = True
            self.cond.notify_all()

    def has_output(self):
        """האם יש כרגע מנה עם מידע לשלוח (מידע חדש או שידור חוזר שפג זמנו)."""
        with self.cond:
            return self._has_output_locked()

    def wait_output(self, timeout):
        """long-poll: ממתין עד שיש מנת-מידע לשלוח, או עד timeout."""
        deadline = time.time() + timeout
        with self.cond:
            while not self._has_output_locked() and not self.closed:
                left = deadline - time.time()
                if left <= 0:
                    return
                self.cond.wait(min(left, RTO / 2))

    # ------------------------------------------------ החוט: בונה / מפרק מנה

    def _due_retransmit(self):
        now = time.time()
        for off in self.inflight:
            if now - self.inflight[off][1] >= RTO:
                return off
        return None

    def _has_output_locked(self):
        new_data = (self.send_ptr - self.send_base) < len(self.send_buf) \
            and (self.send_ptr - self.send_base) < WINDOW
        return new_data or self._due_retransmit() is not None

    def build(self, max_data=MAX_SEG):
        """מחזיר מנה מסוגרת לשליחה: קודם שידור חוזר, אז מידע חדש, אז ack בלבד."""
        with self.cond:
            now = time.time()
            # שידור חוזר של המנה הישנה ביותר שפג זמנה
            due = None
            for off in sorted(self.inflight):
                if now - self.inflight[off][1] >= RTO:
                    due = off
                    break
            if due is not None:
                ln = self.inflight[due][0]
                self.inflight[due][1] = now
                start = due - self.send_base
                data = bytes(self.send_buf[start:start + ln])
                return HDR.pack(1, self.recv_next, due, len(data)) + data

            # מידע חדש בתוך החלון
            inflight_bytes = self.send_ptr - self.send_base
            avail = len(self.send_buf) - inflight_bytes
            if avail > 0 and inflight_bytes < WINDOW:
                take = min(max_data, avail, WINDOW - inflight_bytes)
                start = self.send_ptr - self.send_base
                data = bytes(self.send_buf[start:start + take])
                seq = self.send_ptr
                self.inflight[seq] = [take, now]
                self.send_ptr += take
                return HDR.pack(1, self.recv_next, seq, len(data)) + data

            # אין מה לשלוח — רק אישור קבלה
            return HDR.pack(0, self.recv_next, 0, 0)

    def parse(self, msg):
        """מעבד מנה שהתקבלה: מעדכן אישורים, קולט מידע, מסדר מחדש."""
        if len(msg) < HDR.size:
            return
        flags, ack, seq, dlen = HDR.unpack(msg[:HDR.size])
        data = msg[HDR.size:HDR.size + dlen]
        with self.cond:
            # אישור מצטבר על מה ששלחנו
            if ack > self.send_base:
                del self.send_buf[:ack - self.send_base]
                self.send_base = ack
                if self.send_ptr < self.send_base:
                    self.send_ptr = self.send_base
                for off in list(self.inflight):
                    ln, t = self.inflight[off]
                    if off + ln <= ack:
                        del self.inflight[off]            # אושר במלואו
                    elif off < ack:                       # אושר חלקית — גוזרים
                        del self.inflight[off]
                        self.inflight[ack] = [off + ln - ack, t]
            # קליטת מידע
            if (flags & 1) and data:
                self._recv(seq, bytes(data))
            self.cond.notify_all()

    def _recv(self, seq, data):
        if seq + len(data) <= self.recv_next:
            return                                        # כפילות ישנה לגמרי
        self.recv_hold[seq] = data
        changed = True
        while changed:
            changed = False
            for s in sorted(self.recv_hold):
                d = self.recv_hold[s]
                end = s + len(d)
                if end <= self.recv_next:
                    del self.recv_hold[s]
                    changed = True
                    break
                if s <= self.recv_next < end:
                    self.recv_ready += d[self.recv_next - s:]
                    self.recv_next = end
                    del self.recv_hold[s]
                    changed = True
                    break
