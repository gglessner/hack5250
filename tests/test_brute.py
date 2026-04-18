"""
D1 — FieldBruter. Auto-brute against any input field, response-diff stop.

Live-proven (Mels Cargo, supervisor PIN): r18c23 len=4 numeric. We
hardcoded 32 candidates and hit on '1337'. This is the real version:
charset enumeration, FFW-inferred numeric vs alphanumeric, SQLite
checkpoint, rate limit.

D2 — ProgramEnumerator. The IBM i transaction-enumeration equivalent.
Post-APCT abend, type the program name at the blank screen → restarts.
Names visible at row-2 header (MCMM, MCOR, MCAD). Brute the suffix.
"""
import pytest
import sqlite3
from hackterm_core import Screen


# === Test harness — FakeHack5250 with stateful last_screen ===

class FakeHack5250:
    """Minimal Hack5250 surface for FieldBruter:
      .last_screen   — Screen, mutates after send_field hits the magic value
      .send_field()  — records (row, col, text, aid)
      .send_aid()    — records aid name (D2 uses CLEAR)
    """
    def __init__(self, magic_value=None, fields=None):
        self.sent = []   # list of (row, col, text, aid)
        self.aids_sent = []
        self.magic_value = magic_value
        self._wrong_screen = pytest.mk_screen(fields or [])
        self._wrong_screen.rendered[0] = list("WRONG PIN".ljust(80))
        self._right_screen = pytest.mk_screen(fields or [])
        self._right_screen.rendered[0] = list("ACCESS GRANTED".ljust(80))
        self.last_screen = self._wrong_screen

    def send_field(self, row, col, text, aid_name="ENTER"):
        self.sent.append((row, col, text, aid_name))
        if text == self.magic_value:
            self.last_screen = self._right_screen
        else:
            self.last_screen = self._wrong_screen

    def send_aid(self, aid_name):
        self.aids_sent.append(aid_name)


@pytest.fixture
def db(tmp_path):
    return sqlite3.connect(str(tmp_path / "brute.db"))


# === infer_charset ===

def test_infer_charset_numeric_field(db):
    """FFW shift bits = numeric → charset 'numeric'."""
    from hack5250.attacks.brute import FieldBruter
    h = FakeHack5250(fields=[pytest.mk_field(18, 23, 4, numeric=True)])
    b = FieldBruter(h, db)
    assert b.infer_charset(18, 23) == "numeric"


def test_infer_charset_alpha_field(db):
    from hack5250.attacks.brute import FieldBruter
    h = FakeHack5250(fields=[pytest.mk_field(5, 10, 8, numeric=False)])
    b = FieldBruter(h, db)
    assert b.infer_charset(5, 10) == "alphanumeric"


def test_infer_charset_unknown_position_defaults(db):
    from hack5250.attacks.brute import FieldBruter
    h = FakeHack5250(fields=[])
    b = FieldBruter(h, db)
    assert b.infer_charset(99, 99) == "alphanumeric"


# === _candidates generator ===

def test_candidates_numeric_length_2(db):
    """Numeric, length 2 → 00..99 (100 candidates)."""
    from hack5250.attacks.brute import FieldBruter
    b = FieldBruter(FakeHack5250(), db)
    cands = list(b._candidates("numeric", 2))
    assert len(cands) == 100
    assert cands[0] == "00"
    assert cands[99] == "99"


def test_candidates_resume_from(db):
    """resume_from='05' → start at '06'."""
    from hack5250.attacks.brute import FieldBruter
    b = FieldBruter(FakeHack5250(), db)
    cands = list(b._candidates("numeric", 2, resume_from="05"))
    assert cands[0] == "06"
    assert "05" not in cands


# === _screen_hash ===

def test_screen_hash_differs_on_text_change(db):
    from hack5250.attacks.brute import FieldBruter
    h = FakeHack5250()
    b = FieldBruter(h, db)
    h1 = b._screen_hash()
    h.last_screen = pytest.mk_screen([])
    h.last_screen.rendered[0] = list("DIFFERENT".ljust(80))
    h2 = b._screen_hash()
    assert h1 != h2


# === brute() — the loop ===

def test_brute_finds_magic_value(db):
    """Iterate 00..99, magic is '13' → returns '13'."""
    from hack5250.attacks.brute import FieldBruter
    h = FakeHack5250(magic_value="13")
    b = FieldBruter(h, db)
    hit = b.brute(18, 23, length=2, charset="numeric", rate_limit=0)
    assert hit == "13"
    # 1 baseline send + 14 candidate sends (00..13) = 15
    assert len(h.sent) == 15
    assert h.sent[-1][2] == "13"


def test_brute_no_hit_returns_none(db):
    """No magic value → exhaust candidates → None."""
    from hack5250.attacks.brute import FieldBruter
    h = FakeHack5250(magic_value=None)
    b = FieldBruter(h, db)
    hit = b.brute(1, 1, length=1, charset="numeric", rate_limit=0,
                  max_attempts=5)
    assert hit is None


def test_brute_wordlist_takes_precedence(db):
    """wordlist arg → use that, ignore charset enumeration."""
    from hack5250.attacks.brute import FieldBruter
    h = FakeHack5250(magic_value="ADMIN")
    b = FieldBruter(h, db)
    hit = b.brute(1, 1, length=5, wordlist=["USER", "ADMIN", "ROOT"],
                  rate_limit=0)
    assert hit == "ADMIN"
    # baseline + 2 wordlist sends (USER, ADMIN)
    assert len(h.sent) == 3


def test_brute_checkpoints_to_db(db):
    """Every 50 attempts → SQLite checkpoint with last_tried."""
    from hack5250.attacks.brute import FieldBruter
    h = FakeHack5250(magic_value=None)
    b = FieldBruter(h, db)
    b.brute(1, 1, length=2, charset="numeric", rate_limit=0,
            max_attempts=60)
    cur = db.cursor()
    cur.execute("SELECT last_tried FROM Brutes WHERE row=1 AND col=1")
    row = cur.fetchone()
    assert row is not None
    # last_tried should be around the 50th candidate
    assert row[0] in ("49", "50", "51")  # off-by-one tolerance


# ===========================================================================
# D2 — ProgramEnumerator
# ===========================================================================

class FakeStorage:
    """Storage.all_logs() returns rows: [id, ts, C_S, notes, ?, RAW_DATA, ...].
    We only use index [2] (C_S='S') and [5] (raw bytes)."""
    def __init__(self, raws):
        self.raws = raws
    def all_logs(self):
        return [(i, 0.0, "S", "", None, raw) for i, raw in enumerate(self.raws)]


def _r2_screen_pkt(header_text: str) -> bytes:
    """Build a 5250 packet that, when parsed, has header_text at row 2.

    Need: HDR + ESC + WTD + CC1 CC2 + SBA r=2 c=1 + EBCDIC text + IAC EOR.
    parse() will land text bytes at rendered[1][0:len]."""
    from hack5250.constants import (
        ESC, CMD_WRITE_TO_DISPLAY, ORD_SBA, IAC_EOR,
    )
    from hack5250.tn5250 import TN5250
    from tests.conftest import make_header
    proto = TN5250()
    body = bytes([ESC, CMD_WRITE_TO_DISPLAY, 0x00, 0x00])
    body += bytes([ORD_SBA, 2, 1])
    body += proto.codec.to_ebcdic(header_text)
    return make_header(len(body)) + body + IAC_EOR


def test_harvest_from_history():
    """Scan storage for row-2 program-name pattern."""
    from hack5250.attacks.brute import ProgramEnumerator
    from hack5250.tn5250 import TN5250
    h = FakeHack5250()
    h.protocol = TN5250()
    h.storage = FakeStorage([
        _r2_screen_pkt("MCOR  Order Entry"),
        _r2_screen_pkt("MCAD  Admin"),
        _r2_screen_pkt("MCMM  Main Menu"),
    ])
    pe = ProgramEnumerator(h)
    discovered = pe.harvest_from_history()
    assert "MCOR" in discovered
    assert "MCAD" in discovered
    assert "MCMM" in discovered


def test_harvest_ignores_client_traffic():
    """C_S='C' rows are inbound — no program names there."""
    from hack5250.attacks.brute import ProgramEnumerator
    from hack5250.tn5250 import TN5250
    h = FakeHack5250()
    h.protocol = TN5250()

    class _Storage:
        def all_logs(self):
            return [(0, 0.0, "C", "", None, b"\x00" * 30)]  # client traffic

    h.storage = _Storage()
    pe = ProgramEnumerator(h)
    assert pe.harvest_from_history() == set()


def test_infer_prefix():
    """MCOR, MCAD, MCMM → 'MC'."""
    from hack5250.attacks.brute import ProgramEnumerator
    pe = ProgramEnumerator(FakeHack5250())
    pe.discovered = {"MCOR", "MCAD", "MCMM"}
    assert pe.infer_prefix() == "MC"


def test_infer_prefix_full_overlap():
    """ABCD, ABCE → 'ABC'."""
    from hack5250.attacks.brute import ProgramEnumerator
    pe = ProgramEnumerator(FakeHack5250())
    pe.discovered = {"ABCD", "ABCE"}
    assert pe.infer_prefix() == "ABC"


def test_infer_prefix_too_few_names():
    """Fewer than 2 names → can't infer, return None."""
    from hack5250.attacks.brute import ProgramEnumerator
    pe = ProgramEnumerator(FakeHack5250())
    pe.discovered = {"MCOR"}
    assert pe.infer_prefix() is None


def test_enumerate_skips_known_and_sends_clear():
    """For each candidate: CLEAR, send_field(1,1,cand). Skip already-discovered."""
    from hack5250.attacks.brute import ProgramEnumerator
    h = FakeHack5250()
    # last_screen with empty row-2 → "not found" classification (no callable)
    h.last_screen = pytest.mk_screen([])
    pe = ProgramEnumerator(h)
    pe.discovered = {"MCAA"}  # already known — skip
    # Tiny suffix space: just A,B → MCAA, MCAB, MCBA, MCBB. Skip MCAA.
    pe.enumerate(prefix="MC", suffix_charset="AB", suffix_length=2,
                 rate_limit=0)
    # 3 candidates tried (4 - 1 known)
    candidates = [s[2] for s in h.sent]
    assert "MCAA" not in candidates
    assert "MCAB" in candidates
    assert "MCBA" in candidates
    assert "MCBB" in candidates
    # CLEAR sent before each candidate
    assert h.aids_sent.count("CLEAR") == 3
