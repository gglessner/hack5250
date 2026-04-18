"""
Tests for attacks/preauth.py — Phase 3 Tier A (A1, A3).
A2 (USERVAR injection) is tested in test_tn5250_negotiate.py since
it lives in TN5250.negotiate_hook().
"""
import pytest
from hackterm_core import Screen, Field


# === A3: QDSignonTamperer ===================================================

def _mk_field(row, col, length=10, protected=False, hidden=False):
    """Helper: build a Field with sensible defaults for QDSIGNON tests."""
    return Field(row=row, col=col, length=length, protected=protected,
                 hidden=hidden, numeric=False, mdt=False, content=b"")


@pytest.fixture
def signon_full():
    """A QDSIGNON-shaped screen: 1 protected label + 6 input fields.
    Input fields appear in BUFFER order — that's the IBM mandate."""
    s = Screen.empty()
    s.fields = [
        _mk_field(1, 36, length=7, protected=True),   # "Sign On" label — skipped
        _mk_field(6, 53),                             # USERID
        _mk_field(7, 53, hidden=True),                # PASSWRD (NONDISP)
        _mk_field(8, 53),                             # PROGRAM
        _mk_field(9, 53),                             # MENU
        _mk_field(10, 53),                            # CURLIB
        _mk_field(11, 53, length=128),                # UBUFFER
    ]
    return s


@pytest.fixture
def signon_partial():
    """Minimal sign-on: just USERID + PASSWRD. Many shops strip
    QDSIGNON down to this."""
    s = Screen.empty()
    s.fields = [
        _mk_field(1, 36, length=7, protected=True),
        _mk_field(6, 17),                             # USERID
        _mk_field(7, 17, hidden=True),                # PASSWRD
    ]
    return s


def test_qdsignon_maps_full_layout(signon_full):
    """6 input fields → all 6 buffer-slot names mapped to positions."""
    from hack5250.attacks.preauth import QDSignonTamperer, QDSIGNON_BUFFER_LAYOUT
    t = QDSignonTamperer(signon_full)
    assert len(t.field_positions) == 6
    # All names from the layout constant should be present
    for name, _length in QDSIGNON_BUFFER_LAYOUT:
        assert name in t.field_positions


def test_qdsignon_position_of_program(signon_full):
    """The attack target: where is PROGRAM on this variant?
    Even if NONDISP-hidden, it's the 3rd input field → row 8, col 53."""
    from hack5250.attacks.preauth import QDSignonTamperer
    t = QDSignonTamperer(signon_full)
    assert t.position_of("PROGRAM") == (8, 53)
    assert t.position_of("USERID") == (6, 53)
    assert t.position_of("CURLIB") == (10, 53)


def test_qdsignon_position_of_unknown_returns_none(signon_partial):
    """Stripped-down sign-on: only 2 input fields. PROGRAM/MENU/CURLIB
    aren't mapped → position_of() returns None, not KeyError."""
    from hack5250.attacks.preauth import QDSignonTamperer
    t = QDSignonTamperer(signon_partial)
    assert t.position_of("USERID") == (6, 17)
    assert t.position_of("PASSWRD") == (7, 17)
    assert t.position_of("PROGRAM") is None
    assert t.position_of("UBUFFER") is None


def test_qdsignon_skips_protected_fields(signon_full):
    """The "Sign On" label (row 1, protected) must NOT consume the
    USERID slot. Only unprotected (input) fields map to buffer slots."""
    from hack5250.attacks.preauth import QDSignonTamperer
    t = QDSignonTamperer(signon_full)
    # If protected fields were included, USERID would be at (1, 36)
    assert t.position_of("USERID") != (1, 36)
    assert t.position_of("USERID") == (6, 53)


# === A1: ConfRecEnumerator ==================================================

import socket
import threading


def _make_confrec(code: bytes) -> bytes:
    """Build a synthetic Startup Response Record with the given 4-byte code.
    RFC 4777 §10.3 layout (verified offsets):
      0-1:   length (0x0011 = 17)
      2-3:   record type (0x12A0 — same GDS marker as datastream packets)
      4-11:  reserved/system data (zeroed for tests)
      12-15: 4-byte EBCDIC response code  ← what we're testing
      16:    trailing"""
    assert len(code) == 4
    return bytes([0x00, 0x11, 0x12, 0xA0]) + b"\x00" * 8 + code + b"\x00"


def test_build_environ_structure():
    """The probe payload: USER + IBMSUBSPW + IBMSENDCONFREC=YES, all as
    USERVAR/VALUE pairs. ASCII at the telnet layer (not EBCDIC)."""
    from hack5250.attacks.preauth import ConfRecEnumerator
    e = ConfRecEnumerator("dummy", 0, garbage_password="WRONGPW1")
    env = e._build_environ("QSECOFR")
    # Username uppercased
    assert b"\x03USER\x01QSECOFR" in env
    # Garbage password
    assert b"\x03IBMSUBSPW\x01WRONGPW1" in env
    # The flag that makes the host return a confrec
    assert b"\x03IBMSENDCONFREC\x01YES" in env


def test_classify_confrec_not_found():
    """F0F0F0F2 → user does not exist. The negative case — skip this user."""
    from hack5250.attacks.preauth import ConfRecEnumerator
    e = ConfRecEnumerator("dummy", 0)
    code, desc = e._classify_confrec(_make_confrec(b"\xf0\xf0\xf0\xf2"))
    assert code == "not_found"


def test_classify_confrec_bad_password():
    """F0F0F0F4 → user exists, password wrong. The PRIMARY positive
    signal — this user goes on the brute-force list."""
    from hack5250.attacks.preauth import ConfRecEnumerator
    e = ConfRecEnumerator("dummy", 0)
    code, desc = e._classify_confrec(_make_confrec(b"\xf0\xf0\xf0\xf4"))
    assert code == "bad_password"
    assert "exists" in desc.lower()


def test_classify_confrec_warn_revoke():
    """F0F0F0F8 → next failure revokes. The SAFETY signal —
    enumerate() should stop probing this user. The host literally
    tells us before we'd lock anyone out."""
    from hack5250.attacks.preauth import ConfRecEnumerator
    e = ConfRecEnumerator("dummy", 0)
    code, desc = e._classify_confrec(_make_confrec(b"\xf0\xf0\xf0\xf8"))
    assert code == "warn_revoke"


def test_existing_users_property():
    """Filter results to users that exist (anything except not_found)."""
    from hack5250.attacks.preauth import ConfRecEnumerator
    e = ConfRecEnumerator("dummy", 0)
    e.results = {
        "QSECOFR":  ("bad_password", "..."),
        "NOBODY":   ("not_found", "..."),
        "OLDADMIN": ("disabled", "..."),
        "TESTUSER": ("expired", "..."),
    }
    existing = e.existing_users
    assert "QSECOFR" in existing
    assert "OLDADMIN" in existing
    assert "TESTUSER" in existing
    assert "NOBODY" not in existing
    assert len(existing) == 3


@pytest.fixture
def fake_confrec_server():
    """Thread that accepts one connection, swallows whatever the client
    sends, returns a hardcoded confrec with code F0F0F0F4 (bad_password).
    Yields the bound port. No telnet handshake — probe() must tolerate that."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]

    def serve():
        try:
            conn, _ = sock.accept()
            conn.settimeout(2.0)
            conn.recv(4096)  # swallow the environ subnegotiation
            conn.sendall(_make_confrec(b"\xf0\xf0\xf0\xf4"))
            conn.close()
        except Exception:
            pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield port
    sock.close()


def test_probe_against_fake_responder(fake_confrec_server):
    """Full integration: real socket connect → send → recv → classify.
    Fake server returns bad_password code → probe() should classify it."""
    from hack5250.attacks.preauth import ConfRecEnumerator
    e = ConfRecEnumerator("127.0.0.1", fake_confrec_server)
    code, desc = e.probe("QSECOFR")
    assert code == "bad_password"
    assert e.results["QSECOFR"] == (code, desc)
