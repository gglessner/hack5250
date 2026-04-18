"""
Header alignment regression test — locks in the REAL byte layout.

Bug found 2026-04-08 against live IBM i: our header had a one-byte
alignment error. var_hdr_len at byte 5 (should be 6), opcode at byte 8
(should be 9). Synthetic tests didn't catch it because parse() skips
the entire header (pos = HDR_LEN) without validating layout, and
make_header() in conftest had the SAME wrong layout — round-trip
through our own wrong code = green tests.

These tests pin the layout against a REAL captured packet.
"""
import pytest
from hack5250.tn5250 import TN5250
from hack5250.constants import AID_TABLE, HDR_LEN, OPCODE_PUT_GET
from hack5250.attacks.escape import build_attn_packet


# Captured from a real tn5250 emulator (log id 24 in ibmi_pentest.db,
# 2026-04-08). ENTER key from the MELIS CARGO splash screen.
# This is GROUND TRUTH — built by code that actually works against IBM i.
REAL_ENTER_PACKET = bytes.fromhex("000D12A00000040000030201F1FFEF")


def test_real_packet_structure():
    """Document the real header layout byte-by-byte."""
    p = REAL_ENTER_PACKET
    assert len(p) == 15
    # bytes 0-1: rec_len = 13 (HDR_LEN + body, NOT including IAC EOR)
    assert int.from_bytes(p[0:2], "big") == 13
    assert int.from_bytes(p[0:2], "big") == HDR_LEN + 3  # body = row+col+aid
    # bytes 2-3: GDS type
    assert p[2:4] == b"\x12\xA0"
    # bytes 4-5: TWO reserved bytes (we had only one)
    assert p[4] == 0x00
    assert p[5] == 0x00
    # byte 6: var_hdr_len (we had this at byte 5 — WRONG)
    assert p[6] == 0x04
    # bytes 7-8: flags (we had these at 6-7 — WRONG)
    assert p[7] == 0x00
    assert p[8] == 0x00
    # byte 9: opcode (we had this at byte 8 — WRONG)
    assert p[9] == OPCODE_PUT_GET
    # body: row, col, aid
    assert p[10] == 2     # cursor row
    assert p[11] == 1     # cursor col
    assert p[12] == 0xF1  # ENTER
    # IAC EOR
    assert p[13:15] == b"\xFF\xEF"


def test_build_inbound_matches_real_layout():
    """Our build_inbound() must produce the same header layout as a real emulator."""
    p = TN5250()
    # Build ENTER at cursor (2,1) — same as the captured packet
    ours = p.build_inbound(AID_TABLE["ENTER"], cursor=(2, 1), fields=[])
    assert ours == REAL_ENTER_PACKET, (
        f"\nReal:  {REAL_ENTER_PACKET.hex()}"
        f"\nOurs:  {ours.hex()}"
        f"\nDiffs: {[(i, r, o) for i, (r, o) in enumerate(zip(REAL_ENTER_PACKET, ours)) if r != o]}"
    )


def test_rec_len_excludes_iac_eor():
    """rec_len at bytes 0-1 does NOT include the trailing IAC EOR.

    Emulator: len=13, packet=15. 15 - 2 (IAC EOR) = 13 = HDR_LEN(10) + body(3).
    """
    p = TN5250()
    pkt = p.build_inbound(AID_TABLE["F5"], cursor=(1, 1), fields=[])
    rec_len = int.from_bytes(pkt[0:2], "big")
    assert rec_len == len(pkt) - 2  # excludes IAC EOR
    assert rec_len == HDR_LEN + 3   # header + (row, col, aid)


def test_var_hdr_len_at_byte_6():
    """The var_hdr_len byte (always 0x04) is at offset 6, not 5."""
    p = TN5250()
    pkt = p.build_inbound(AID_TABLE["ENTER"], cursor=(1, 1), fields=[])
    assert pkt[5] == 0x00  # reserved
    assert pkt[6] == 0x04  # var_hdr_len


def test_opcode_at_byte_9():
    """The opcode byte is at offset 9, not 8."""
    p = TN5250()
    pkt = p.build_inbound(AID_TABLE["ENTER"], cursor=(1, 1), fields=[])
    assert pkt[8] == 0x00  # flags lo
    assert pkt[9] == OPCODE_PUT_GET


def test_attn_packet_header_layout():
    """build_attn_packet has the same header — same alignment bug.

    ATTN sets a flag bit, not an AID. With the correct layout,
    flags are at bytes 7-8 (not 6-7), so ATN goes in byte 7.
    """
    pkt = build_attn_packet()
    assert pkt[5] == 0x00   # reserved (was 0x04)
    assert pkt[6] == 0x04   # var_hdr_len (was 0x00 or flags)
    # ATN flag should be in the flags bytes (7-8), not byte 6
    assert pkt[7] != 0x00 or pkt[8] != 0x00  # SOME flag bit set
    assert pkt[9] == 0x00   # opcode = NONE for ATTN


def test_attn_rec_len_excludes_iac_eor():
    pkt = build_attn_packet()
    rec_len = int.from_bytes(pkt[0:2], "big")
    assert rec_len == len(pkt) - 2
    assert rec_len == HDR_LEN  # ATTN has no body


def test_with_field_data_layout_unchanged():
    """The body format (after byte 10) was always correct — only the
    header was misaligned. Verify body still works."""
    from hackterm_core import FieldWrite
    p = TN5250()
    pkt = p.build_inbound(
        AID_TABLE["ENTER"], cursor=(6, 17),
        fields=[FieldWrite(row=6, col=17, data=b"\xC1\xC2\xC3")],  # ABC
    )
    # Header (10) + row col aid (3) + SBA row col (3) + data (3) = 19
    assert int.from_bytes(pkt[0:2], "big") == 19
    assert pkt[9] == OPCODE_PUT_GET
    # Body unchanged
    assert pkt[10] == 6   # cursor row
    assert pkt[11] == 17  # cursor col
    assert pkt[12] == 0xF1  # ENTER
    assert pkt[13] == 0x11  # SBA
    assert pkt[14] == 6   # field row
    assert pkt[15] == 17  # field col
    assert pkt[16:19] == b"\xC1\xC2\xC3"
