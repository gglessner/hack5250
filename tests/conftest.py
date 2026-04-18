"""
Synthetic 5250 datastream fixtures.

Each fixture is a hand-crafted byte sequence with documented structure.
These are NOT captured from a real IBM i — they're built from the spec.
Real-world validation against PUB400 pcaps comes later.
"""
import sys
import os
import pytest

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_root, "hackterm-core"))
sys.path.insert(0, _root)

from hack5250.constants import (
    HDR_LEN, ESC, CMD_WRITE_TO_DISPLAY, CMD_CLEAR_UNIT,
    ORD_SOH, ORD_SBA, ORD_SF, ORD_IC,
    FFW_ID, FFW_BYPASS, FFW_MDT, SHIFT_NUMERIC_ONLY,
    ATTR_GREEN, ATTR_NONDISP, ATTR_WHITE,
    OPCODE_PUT_GET, IAC_EOR,
)


def make_header(body_len: int, opcode: int = OPCODE_PUT_GET, flags: int = 0) -> bytes:
    """Build a 10-byte RFC 1205 header for a body of body_len bytes.

    Layout verified against real emulator capture (2026-04-08).
    Previous version had a one-byte left-shift (var_hdr_len at byte 5
    instead of 6, opcode at 8 instead of 9). parse() never noticed
    because it does pos=HDR_LEN and skips the whole header.

    body_len should NOT include IAC EOR — rec_len excludes it.
    The fixtures below pass `len(body) + 2` which IS wrong (overcounts
    by 2) but parse() doesn't validate rec_len so it doesn't matter
    for outbound test packets. Inbound packets (build_inbound) DO need
    the correct length because the host validates.
    """
    rec_len = HDR_LEN + body_len
    return bytes([
        (rec_len >> 8) & 0xFF, rec_len & 0xFF,   # 0-1: length
        0x12, 0xA0,                               # 2-3: GDS type
        0x00, 0x00,                               # 4-5: reserved (TWO bytes)
        0x04,                                     # 6:   var hdr len
        (flags >> 8) & 0xFF, flags & 0xFF,        # 7-8: flags (16-bit)
        opcode,                                   # 9:   opcode
    ])


def make_ffw(bypass=False, mdt=False, numeric=False, mand_entry=False) -> bytes:
    """Build a 2-byte FFW with specified bits set."""
    w = FFW_ID
    if bypass:     w |= FFW_BYPASS
    if mdt:        w |= FFW_MDT
    if numeric:    w |= SHIFT_NUMERIC_ONLY
    if mand_entry: w |= 0x0008
    return bytes([(w >> 8) & 0xFF, w & 0xFF])


@pytest.fixture
def pkt_minimal():
    """Smallest valid outbound: header + ESC + Clear Unit + IAC EOR.

    No fields, no text. Tests that the parser doesn't crash on empty screens.
    """
    body = bytes([ESC, CMD_CLEAR_UNIT])
    return make_header(len(body) + 2) + body + IAC_EOR


@pytest.fixture
def pkt_one_input_field():
    """One unprotected input field at row 5, col 10, length 8, green.

    Structure:
      [10-byte header]
      ESC CMD_WRITE_TO_DISPLAY CC1 CC2
        SBA row=5 col=10
        SF FFW(input,no-bypass) attr=green len=8
      IAC EOR
    """
    body = bytes([ESC, CMD_WRITE_TO_DISPLAY, 0x00, 0x00])  # CC1=0, CC2=0
    body += bytes([ORD_SBA, 5, 10])
    body += bytes([ORD_SF]) + make_ffw(bypass=False) + bytes([ATTR_GREEN, 0x00, 0x08])
    return make_header(len(body) + 2) + body + IAC_EOR


@pytest.fixture
def pkt_protected_field():
    """One PROTECTED field — bypass bit set in FFW.

    This is the unprotect target. mutate(unprotect=True) should clear FFW_BYPASS.
    """
    body = bytes([ESC, CMD_WRITE_TO_DISPLAY, 0x00, 0x00])
    body += bytes([ORD_SBA, 1, 1])
    body += bytes([ORD_SF]) + make_ffw(bypass=True) + bytes([ATTR_GREEN, 0x00, 0x10])
    return make_header(len(body) + 2) + body + IAC_EOR


@pytest.fixture
def pkt_hidden_field():
    """Field with ATTR_NONDISP — hidden text.

    This is the reveal_hidden target. mutate(reveal_hidden=True) should
    rewrite 0x27 → 0x20 (or 0x22 if high_visibility).
    """
    body = bytes([ESC, CMD_WRITE_TO_DISPLAY, 0x00, 0x00])
    body += bytes([ORD_SBA, 3, 5])
    body += bytes([ORD_SF]) + make_ffw() + bytes([ATTR_NONDISP, 0x00, 0x0C])
    # Some hidden text after the field def: "SECRET" in EBCDIC
    body += bytes([0xE2, 0xC5, 0xC3, 0xD9, 0xC5, 0xE3])
    return make_header(len(body) + 2) + body + IAC_EOR


@pytest.fixture
def pkt_numeric_field():
    """Numeric-only field — FFW shift bits = 011.

    Target for remove_numeric: mutate should zero the shift bits.
    """
    body = bytes([ESC, CMD_WRITE_TO_DISPLAY, 0x00, 0x00])
    body += bytes([ORD_SBA, 7, 20])
    body += bytes([ORD_SF]) + make_ffw(numeric=True) + bytes([ATTR_GREEN, 0x00, 0x06])
    return make_header(len(body) + 2) + body + IAC_EOR


@pytest.fixture
def pkt_with_soh():
    """Includes SOH order with PF-key mask. Only F3 and F12 enabled.

    SOH structure: ORD_SOH + len(1) + flags(1) + resv(1) + resv(1) + err_row(1) + pf_mask(3)
    pf_mask is 24-bit big-endian, bit N (from MSB) = F(N+1) enabled.
    F3 = bit 2 = 0x200000, F12 = bit 11 = 0x001000
    Combined: 0x201000 = bytes 20 10 00
    """
    body = bytes([ESC, CMD_WRITE_TO_DISPLAY, 0x00, 0x00])
    body += bytes([ORD_SOH, 0x07, 0x00, 0x00, 0x00, 0x18, 0x20, 0x10, 0x00])
    body += bytes([ORD_SBA, 1, 1])
    body += bytes([ORD_SF]) + make_ffw() + bytes([ATTR_GREEN, 0x00, 0x04])
    return make_header(len(body) + 2) + body + IAC_EOR


@pytest.fixture
def pkt_signon_screen():
    """Realistic-ish IBM i sign-on screen: User, Password (hidden), one text label.

    Layout:
      Row 1: "Sign On" label (output-only field, no FFW)
      Row 6: User input field (10 chars, alpha)
      Row 7: Password input field (10 chars, NONDISP)
    """
    body = bytes([ESC, CMD_CLEAR_UNIT])
    body += bytes([ESC, CMD_WRITE_TO_DISPLAY, 0x00, 0x00])
    # Row 1, col 36: "Sign On" — output-only (SF without FFW: just attr+len)
    body += bytes([ORD_SBA, 1, 36])
    body += bytes([ORD_SF, ATTR_WHITE, 0x00, 0x07])  # no FFW (top bits of 0x22 != 01)
    body += bytes([0xE2, 0x89, 0x87, 0x95, 0x40, 0xD6, 0x95])  # "Sign On" EBCDIC
    # Row 6, col 17: User field
    body += bytes([ORD_SBA, 6, 17])
    body += bytes([ORD_SF]) + make_ffw() + bytes([ATTR_GREEN, 0x00, 0x0A])
    # Row 7, col 17: Password field — NONDISP
    body += bytes([ORD_SBA, 7, 17])
    body += bytes([ORD_SF]) + make_ffw() + bytes([ATTR_NONDISP, 0x00, 0x0A])
    body += bytes([ORD_IC, 6, 17])  # cursor on user field
    return make_header(len(body) + 2) + body + IAC_EOR


@pytest.fixture
def ibmrseed_offer():
    """RFC 2877 server→client: offer IBMRSEED with 8-byte seed.

    IAC SB NEW-ENVIRON SEND USERVAR "IBMRSEED" <8-byte-seed> IAC SE
    """
    seed = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    return (bytes([0xFF, 0xFA, 0x27, 0x01, 0x03]) + b"IBMRSEED" + seed +
            bytes([0xFF, 0xF0]))


@pytest.fixture
def cleartext_password_response():
    """RFC 2877 client→server: cleartext password (no IBMRSEED, just IBMSUBSPW).

    IAC SB NEW-ENVIRON IS USERVAR "USER" VALUE "QSECOFR"
                          USERVAR "IBMSUBSPW" VALUE "PASSWORD" IAC SE
    """
    return (bytes([0xFF, 0xFA, 0x27, 0x00]) +
            bytes([0x03]) + b"USER" + bytes([0x01]) + b"QSECOFR" +
            bytes([0x03]) + b"IBMSUBSPW" + bytes([0x01]) + b"PASSWORD" +
            bytes([0xFF, 0xF0]))


# Re-export helpers for tests that build packets inline
pytest.make_header = make_header
pytest.make_ffw = make_ffw


# ---------------------------------------------------------------------------
# FakeDaemon — drop-in for ProxyDaemon in observer-pattern unit tests.
# Mirrors hack3270's tests/conftest.py FakeDaemon. No sockets.
# ---------------------------------------------------------------------------

class FakeDaemon:
    """Drop-in for ProxyDaemon in unit tests. No sockets — pure in-memory.

    Test-driver helpers (NOT on real ProxyDaemon):
      .fire_s2c(data)  — simulate server→client traffic, calls observers
      .fire_c2s(data)  — simulate client→server, calls observers
      .sent_to_server  — list of bytes from inject_to_server() calls
      .sent_to_client  — list of bytes from inject_to_client() calls
    """

    def __init__(self):
        self._observers = []
        self.sent_to_server = []
        self.sent_to_client = []

    def add_observer(self, fn):
        self._observers.append(fn)

    def inject_to_server(self, data: bytes):
        self.sent_to_server.append(data)

    def inject_to_client(self, data: bytes):
        self.sent_to_client.append(data)

    def fire_s2c(self, data: bytes):
        """Simulate server→client traffic hitting observers."""
        for obs in self._observers:
            obs(data, "s2c")

    def fire_c2s(self, data: bytes):
        """Simulate client→server traffic hitting observers."""
        for obs in self._observers:
            obs(data, "c2s")


@pytest.fixture
def fake_daemon():
    return FakeDaemon()


# ===========================================================================
# Phase 3 RPG fixtures — FakeDaemon + synthetic Screen builders
# ===========================================================================

from hackterm_core import Screen, Field
from hackterm_core.protocol import NegotiateOpts, MutateOpts


def mk_field(row, col, length, protected=False, hidden=False,
             numeric=False, content=b""):
    """Build a Field dataclass directly — no parse() round-trip."""
    return Field(row=row, col=col, length=length, protected=protected,
                 hidden=hidden, numeric=numeric, mdt=False, content=content)


def mk_screen(fields, header_text="MCOR    ", rows=24, cols=80):
    """Build a Screen with given fields and a row-2 header.

    header_text goes at rendered[1][0:len] — ExfmtDiffer._same_format()
    keys on it. Default 'MCOR' mimics Mels Cargo program ID.
    """
    s = Screen.empty(rows=rows, cols=cols)
    s.fields = list(fields)
    s.raw = b""  # caller doesn't need raw for diff tests
    # Paint header into row 2 (index 1)
    for i, ch in enumerate(header_text[:cols]):
        s.rendered[1][i] = ch
    return s


# Re-export for inline use in tests
pytest.mk_field = mk_field
pytest.mk_screen = mk_screen


class FakeDaemon:
    """Drop-in for ProxyDaemon in unit tests. No sockets.

    Direct copy of /tests/conftest.py:290-342 (hack3270 root conftest).
    Lives here so hack5250's tests are self-contained.

    Test-driver helpers (NOT on real ProxyDaemon):
      .fire_s2c(data)   — simulate server→client traffic, calls observers
      .fire_c2s(data)   — simulate client→server, calls intercept then observers
      .sent_to_server   — list of bytes from inject_to_server() calls
    """

    def __init__(self):
        self.negotiate_opts = NegotiateOpts()
        self.mutate_opts = MutateOpts()
        self.handshake_complete = True
        self._observers = []
        self._client_intercept = None
        self.sent_to_server = []
        self.sent_to_client = []

    def add_observer(self, fn):
        self._observers.append(fn)

    def remove_observer(self, fn):
        try:
            self._observers.remove(fn)
        except ValueError:
            pass

    def set_client_intercept(self, fn):
        self._client_intercept = fn

    def inject_to_server(self, data):
        self.sent_to_server.append(data)

    def inject_to_client(self, data):
        self.sent_to_client.append(data)

    def fire_s2c(self, data):
        for obs in self._observers:
            obs(data, "s2c")

    def fire_c2s(self, data):
        if self._client_intercept:
            data = self._client_intercept(data)
            if data is None:
                return None
        for obs in self._observers:
            obs(data, "c2s")
        return data


@pytest.fixture
def fake_daemon():
    return FakeDaemon()
