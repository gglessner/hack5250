"""Lock down 5250 byte values. If any of these change, the parser breaks.

Sources cited inline. Disagreements between sources noted.
"""
from hack5250.constants import (
    HDR_LEN, ESC,
    CMD_WRITE_TO_DISPLAY, CMD_CLEAR_UNIT, CMD_READ_MDT_FIELDS,
    CMD_READ_INPUT_FIELDS, CMD_WRITE_STRUCTURED,
    ORD_SOH, ORD_RA, ORD_SBA, ORD_IC, ORD_SF, ORD_TD,
    FFW_ID, FFW_ID_MASK, FFW_BYPASS, FFW_DUP, FFW_MDT,
    FFW_SHIFT_MASK, FFW_AUTO_ENTER, FFW_FER, FFW_MONOCASE, FFW_MAND_ENTRY,
    FCW_ID, FCW_ID_MASK,
    ATTR_GREEN, ATTR_WHITE, ATTR_NONDISP, ATTR_RED,
    AID_TABLE,
    OPCODE_PUT_GET, OPCODE_INVITE,
)


def test_header_length():
    """RFC 1205 §3: 10-byte record header before datastream."""
    assert HDR_LEN == 10


def test_escape_byte():
    """5250 datastream commands are preceded by ESC (0x04).
    Source: lib5250/codes5250.h, Wireshark packet-tn5250.c"""
    assert ESC == 0x04


def test_command_opcodes():
    """Source: lib5250/codes5250.h"""
    assert CMD_WRITE_TO_DISPLAY == 0x11
    assert CMD_CLEAR_UNIT == 0x40
    assert CMD_READ_MDT_FIELDS == 0x52
    assert CMD_READ_INPUT_FIELDS == 0x42
    assert CMD_WRITE_STRUCTURED == 0xF3


def test_order_bytes():
    """Source: lib5250/codes5250.h, SC30-3533 §15.6"""
    assert ORD_SOH == 0x01
    assert ORD_RA == 0x02
    assert ORD_SBA == 0x11   # NOTE: same byte as CMD_WRITE_TO_DISPLAY — context disambiguates
    assert ORD_IC == 0x13
    assert ORD_SF == 0x1D    # NOTE: same byte as 3270 SF — but different following structure
    assert ORD_TD == 0x10


def test_ffw_marker():
    """FFW is identified by top bits = 01.
    Source: Wireshark packet-tn5250.c (FFW_ID = 0x40 in single-byte view,
    0x4000 when treated as 16-bit big-endian word)."""
    assert FFW_ID == 0x4000
    assert FFW_ID_MASK == 0xC000
    # An FFW word with just the marker set
    assert (0x4000 & FFW_ID_MASK) == FFW_ID
    # A non-FFW word (FCW or text)
    assert (0x8000 & FFW_ID_MASK) != FFW_ID


def test_ffw_attack_target_bits():
    """The bits we manipulate. Source: SC30-3533 §15.6.12.3 via Wireshark."""
    assert FFW_BYPASS == 0x2000      # protected — clear this to unprotect
    assert FFW_MDT == 0x0800
    assert FFW_SHIFT_MASK == 0x0700  # numeric/alpha — clear for remove_numeric
    assert FFW_MAND_ENTRY == 0x0008
    assert FFW_FER == 0x0040         # field-exit-required


def test_ffw_other_bits():
    assert FFW_DUP == 0x1000
    assert FFW_AUTO_ENTER == 0x0080
    assert FFW_MONOCASE == 0x0020


def test_fcw_marker():
    """FCW (Field Control Word) follows FFW, top bits = 10."""
    assert FCW_ID == 0x8000
    assert FCW_ID_MASK == 0xC000
    assert (0x8000 & FCW_ID_MASK) == FCW_ID


def test_screen_attributes():
    """Source: lib5250/codes5250.h. Range 0x20-0x3F.
    0x27 (NONDISP) is the reveal_hidden target."""
    assert ATTR_GREEN == 0x20
    assert ATTR_WHITE == 0x22
    assert ATTR_NONDISP == 0x27
    assert ATTR_RED == 0x28
    # All attributes are in the 0x20-0x3F range
    for attr in (ATTR_GREEN, ATTR_WHITE, ATTR_NONDISP, ATTR_RED):
        assert 0x20 <= attr <= 0x3F


def test_aid_enter_differs_from_3270():
    """5250 ENTER is 0xF1. 3270 ENTER is 0x7D, and 0xF1 is PF1.
    This collision is why aid_table MUST be protocol-scoped."""
    assert AID_TABLE["ENTER"] == 0xF1


def test_aid_function_keys():
    """F1-F12 are 0x31-0x3C (contiguous, unlike 3270's scattered PF keys).
    F13-F24 are 0xB1-0xBC. Source: Wireshark packet-tn5250.c"""
    for i in range(1, 13):
        assert AID_TABLE[f"F{i}"] == 0x30 + i
    for i in range(13, 25):
        assert AID_TABLE[f"F{i}"] == 0xA4 + i


def test_aid_special_keys():
    assert AID_TABLE["CLEAR"] == 0xBD
    assert AID_TABLE["HELP"] == 0xF3
    assert AID_TABLE["ROLLDN"] == 0xF4
    assert AID_TABLE["ROLLUP"] == 0xF5
    assert AID_TABLE["PRINT"] == 0xF6


def test_aid_pa_keys_match_3270():
    """PA1/PA2/PA3 are the SAME values as 3270 — lucky reuse."""
    assert AID_TABLE["PA1"] == 0x6C
    assert AID_TABLE["PA2"] == 0x6E
    assert AID_TABLE["PA3"] == 0x6B


def test_header_opcodes():
    """RFC 1205 §3 byte 8 (opcode)."""
    assert OPCODE_PUT_GET == 0x03
    assert OPCODE_INVITE == 0x01


def test_aid_table_completeness():
    """Should have ENTER + F1-24 + ROLLUP/DN + HELP + PRINT + CLEAR + PA1-3 = 33 keys minimum."""
    assert len(AID_TABLE) >= 33
