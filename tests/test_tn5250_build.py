import pytest
from hack5250.tn5250 import TN5250
from hack5250.constants import AID_TABLE, HDR_LEN, ORD_SBA, IAC_EOR, OPCODE_PUT_GET
from hackterm_core import FieldWrite


@pytest.fixture
def proto():
    return TN5250()


def test_build_minimal_enter(proto):
    """ENTER with no field data — short-read AID."""
    pkt = proto.build_inbound(AID_TABLE["ENTER"], cursor=(1, 1), fields=[])
    # Should be: header(10) + row(1) + col(1) + AID(1) + IAC EOR(2) = 15 bytes
    assert len(pkt) == 15
    assert pkt[-2:] == IAC_EOR


def test_build_aid_position(proto):
    """5250 inbound: cursor BEFORE aid (3270 has aid first).
    Body starts at HDR_LEN: row, col, aid."""
    pkt = proto.build_inbound(AID_TABLE["F3"], cursor=(5, 10), fields=[])
    assert pkt[HDR_LEN] == 5       # cursor row
    assert pkt[HDR_LEN + 1] == 10  # cursor col
    assert pkt[HDR_LEN + 2] == AID_TABLE["F3"]  # AID comes third


def test_build_with_one_field(proto):
    """Field data is SBA + row + col + EBCDIC bytes."""
    fw = FieldWrite(row=6, col=17, data=b"\xD8\xE2\xC5\xC3\xD6\xC6\xD9")  # QSECOFR
    pkt = proto.build_inbound(AID_TABLE["ENTER"], cursor=(6, 17), fields=[fw])
    body = pkt[HDR_LEN:-2]  # strip header and IAC EOR
    # body = row col aid SBA frow fcol data
    assert body[0] == 6   # cursor row
    assert body[1] == 17  # cursor col
    assert body[2] == AID_TABLE["ENTER"]
    assert body[3] == ORD_SBA
    assert body[4] == 6   # field row
    assert body[5] == 17  # field col
    assert body[6:] == b"\xD8\xE2\xC5\xC3\xD6\xC6\xD9"


def test_build_with_multiple_fields(proto):
    """Multiple fields → multiple SBA blocks."""
    fields = [
        FieldWrite(row=6, col=17, data=b"\xC1\xC2\xC3"),  # ABC
        FieldWrite(row=7, col=17, data=b"\xF1\xF2\xF3"),  # 123
    ]
    pkt = proto.build_inbound(AID_TABLE["ENTER"], cursor=(6, 17), fields=fields)
    body = pkt[HDR_LEN:-2]
    # First field at offset 3 (after row+col+aid)
    assert body[3] == ORD_SBA and body[4] == 6 and body[5] == 17
    assert body[6:9] == b"\xC1\xC2\xC3"
    # Second field follows immediately
    assert body[9] == ORD_SBA and body[10] == 7 and body[11] == 17
    assert body[12:15] == b"\xF1\xF2\xF3"


def test_build_header_length_correct(proto):
    """Header bytes 0-1 = record length: header + body, EXCLUDING IAC EOR.
    Verified against real emulator capture (rec_len=13, packet=15)."""
    pkt = proto.build_inbound(AID_TABLE["ENTER"], cursor=(1, 1), fields=[])
    rec_len = (pkt[0] << 8) | pkt[1]
    assert rec_len == len(pkt) - 2  # IAC EOR not counted


def test_build_header_opcode(proto):
    """Header byte 9 = opcode (corrected 2026-04-08 — was at byte 8,
    one position too early). Inbound is PUT_GET."""
    pkt = proto.build_inbound(AID_TABLE["ENTER"], cursor=(1, 1), fields=[])
    assert pkt[9] == OPCODE_PUT_GET


def test_build_header_gds_type(proto):
    """Header bytes 2-3 = 0x12A0 (General Data Stream)."""
    pkt = proto.build_inbound(AID_TABLE["ENTER"], cursor=(1, 1), fields=[])
    assert pkt[2] == 0x12
    assert pkt[3] == 0xA0


def test_spoof_aid_replaces_correct_byte(proto):
    """5250 AID is at HDR_LEN + 2 (after cursor row+col)."""
    original = proto.build_inbound(AID_TABLE["ENTER"], cursor=(1, 1), fields=[])
    spoofed = proto.spoof_aid(original, AID_TABLE["F12"])
    # Only one byte should differ
    diffs = [(i, a, b) for i, (a, b) in enumerate(zip(original, spoofed)) if a != b]
    assert len(diffs) == 1
    idx, before, after = diffs[0]
    assert idx == HDR_LEN + 2
    assert before == AID_TABLE["ENTER"]
    assert after == AID_TABLE["F12"]


def test_spoof_aid_preserves_length(proto):
    original = proto.build_inbound(AID_TABLE["ENTER"], cursor=(5, 5),
                                   fields=[FieldWrite(5, 5, b"\xC1\xC2")])
    spoofed = proto.spoof_aid(original, AID_TABLE["CLEAR"])
    assert len(spoofed) == len(original)


def test_spoof_aid_too_short_returns_unchanged(proto):
    """Defensive: packets shorter than HDR_LEN+3 can't have an AID."""
    short = b"\x00" * 5
    assert proto.spoof_aid(short, 0xF1) == short
