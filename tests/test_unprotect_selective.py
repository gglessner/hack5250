"""
Selective unprotect: only clear FFW BYPASS on fields that are also hidden.

Live finding (Mels Cargo, 2026-04-08): unconditional unprotect cleared
BYPASS on 97 fields, exploding the emulator's format table. Tab order
went through 97 extra stops; navigation broke.

The interesting protected fields are the HIDDEN ones — visible protected
fields are just decorative output. New behavior: unprotect only fires
on fields where the screen-attribute byte is also NONDISP.

This makes unprotect+reveal_hidden the natural pair: reveal shows you
what was there, unprotect lets you type into it. Both target the same
field set. Decorative output is left alone.
"""
import pytest
from hack5250.tn5250 import TN5250
from hack5250.constants import (
    ESC, CMD_WRITE_TO_DISPLAY, ORD_SBA, ORD_SF,
    FFW_ID, FFW_BYPASS, ATTR_GREEN, ATTR_BLUE, ATTR_NONDISP,
)
from hackterm_core import MutateOpts
from tests.conftest import make_header, make_ffw


def _packet_with_two_protected_fields(attr1: int, attr2: int) -> bytes:
    """One protected field with attr1, one with attr2. Same FFW (BYPASS set)."""
    body = bytes([ESC, CMD_WRITE_TO_DISPLAY, 0x00, 0x00])
    # Field 1: protected, attr1
    body += bytes([ORD_SBA, 5, 5])
    body += bytes([ORD_SF]) + make_ffw(bypass=True) + bytes([attr1, 0x00, 0x0A])
    # Field 2: protected, attr2
    body += bytes([ORD_SBA, 10, 5])
    body += bytes([ORD_SF]) + make_ffw(bypass=True) + bytes([attr2, 0x00, 0x0A])
    return make_header(len(body)) + body + b"\xff\xef"


def test_unprotect_skips_visible_protected_field():
    """Protected + visible (ATTR_GREEN) → BYPASS stays set. This is the
    decorative-output case that broke navigation."""
    pkt = _packet_with_two_protected_fields(ATTR_GREEN, ATTR_GREEN)
    out = TN5250().mutate(pkt, MutateOpts(unprotect=True))
    # No bytes should change — neither field is hidden
    assert out == pkt


def test_unprotect_fires_on_hidden_protected_field():
    """Protected + hidden (ATTR_NONDISP) → BYPASS cleared. This is the
    actual attack target."""
    pkt = _packet_with_two_protected_fields(ATTR_NONDISP, ATTR_NONDISP)
    out = TN5250().mutate(pkt, MutateOpts(unprotect=True))
    s = TN5250().parse(out)
    assert all(not f.protected for f in s.fields)


def test_unprotect_selective_one_hidden_one_visible():
    """The crucial case: mixed screen. Only the hidden one gets unprotected."""
    pkt = _packet_with_two_protected_fields(ATTR_GREEN, ATTR_NONDISP)
    out = TN5250().mutate(pkt, MutateOpts(unprotect=True))
    s = TN5250().parse(out)
    # Field 1 (green, visible) stays protected
    assert s.fields[0].protected is True
    # Field 2 (nondisp, hidden) gets unprotected
    assert s.fields[1].protected is False


def test_unprotect_byte_count_against_real_packet():
    """Real Mels Cargo menu: 97 protected fields, only 4 hidden.
    Selective unprotect should change 4 FFW high bytes (one per hidden
    field), NOT 97. Plus 3 SOH mask bytes = 7 total."""
    import sqlite3
    db = sqlite3.connect("/home/kali/hack3270-update/hack5250/ibmi_pentest.db")
    cur = db.cursor()
    cur.execute("SELECT RAW_DATA FROM Logs WHERE ID=248")
    row = cur.fetchone()
    db.close()
    if row is None:
        pytest.skip("Mels Cargo capture not in db")
    raw = bytes(row[0])

    out = TN5250().mutate(raw, MutateOpts(unprotect=True))
    diffs = sum(1 for a, b in zip(raw, out) if a != b)
    # Was 100 (97 FFW + 3 SOH). After selective: 7 (4 FFW + 3 SOH).
    # After SOH-rewrite removal (X-SYSTEM lock): 4 FFW only.
    assert diffs == 4, f"expected 4 surgical changes, got {diffs}"


def test_unprotect_plus_reveal_natural_pair():
    """The two together: hidden field becomes visible AND editable.
    Visible protected fields are completely untouched."""
    pkt = _packet_with_two_protected_fields(ATTR_BLUE, ATTR_NONDISP)
    out = TN5250().mutate(pkt, MutateOpts(unprotect=True, reveal_hidden=True))
    s = TN5250().parse(out)
    # Blue field: completely unchanged
    assert s.fields[0].protected is True
    assert s.fields[0].hidden is False
    # Hidden field: revealed AND unprotected
    assert s.fields[1].protected is False
    assert s.fields[1].hidden is False


def test_unprotect_already_unprotected_unchanged():
    """Field with no BYPASS bit (already input) — leave it alone regardless
    of attr. Don't accidentally SET bypass on input fields."""
    body = bytes([ESC, CMD_WRITE_TO_DISPLAY, 0x00, 0x00])
    body += bytes([ORD_SBA, 5, 5])
    body += bytes([ORD_SF]) + make_ffw(bypass=False) + bytes([ATTR_NONDISP, 0x00, 0x0A])
    pkt = make_header(len(body)) + body + b"\xff\xef"

    out = TN5250().mutate(pkt, MutateOpts(unprotect=True))
    # FFW should be unchanged (already had no BYPASS)
    s_orig = TN5250().parse(pkt)
    s_mut = TN5250().parse(out)
    assert s_orig.fields[0].protected == s_mut.fields[0].protected == False


def test_remove_numeric_still_unconditional():
    """remove_numeric is independent of attr — it's always safe (changes
    input validation, doesn't affect format-table membership)."""
    body = bytes([ESC, CMD_WRITE_TO_DISPLAY, 0x00, 0x00])
    body += bytes([ORD_SBA, 5, 5])
    # Numeric field, visible (green)
    body += bytes([ORD_SF]) + make_ffw(numeric=True) + bytes([ATTR_GREEN, 0x00, 0x0A])
    pkt = make_header(len(body)) + body + b"\xff\xef"

    out = TN5250().mutate(pkt, MutateOpts(remove_numeric=True))
    s = TN5250().parse(out)
    assert s.fields[0].numeric is False  # numeric cleared even on visible field
