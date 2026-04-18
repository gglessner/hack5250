import pytest
from hack5250.attacks.escape import (
    build_attn_packet, get_masked_keys, classify_attn_response,
)
from hack5250.constants import HDR_LEN, HDR_FLAG_ATN, AID_TABLE
from hackterm_core import Screen


def test_build_attn_packet_sets_atn_flag():
    """ATTN is signaled via header flag bit, not an AID byte.
    Flags are 16-bit at offsets 7-8 (corrected 2026-04-08); ATN is in
    the high byte (offset 7)."""
    pkt = build_attn_packet()
    assert (pkt[7] & HDR_FLAG_ATN) == HDR_FLAG_ATN


def test_build_attn_packet_no_aid():
    """ATTN packets have no body — just header + IAC EOR."""
    pkt = build_attn_packet()
    assert len(pkt) == HDR_LEN + 2  # header + IAC EOR


def test_get_masked_keys_all_enabled():
    """pf_mask 0xFFFFFF means all 24 keys enabled — none masked."""
    s = Screen.empty()
    s.pf_mask = 0xFFFFFF
    assert get_masked_keys(s) == []


def test_get_masked_keys_only_f3_enabled():
    """If only F3 is enabled (bit 2 from MSB), F1,F2,F4-F24 are masked."""
    s = Screen.empty()
    s.pf_mask = 0x200000  # bit 2 set
    masked = get_masked_keys(s)
    assert "F3" not in masked
    assert "F1" in masked
    assert "F12" in masked
    assert "F24" in masked
    assert len(masked) == 23


def test_get_masked_keys_f3_and_f12():
    """The pkt_with_soh fixture has F3+F12 enabled (mask 0x201000)."""
    s = Screen.empty()
    s.pf_mask = 0x201000
    masked = get_masked_keys(s)
    assert "F3" not in masked
    assert "F12" not in masked
    assert "F1" in masked
    assert len(masked) == 22


def test_get_masked_keys_no_pf_mask_attribute():
    """Screen without pf_mask (no SOH seen) → assume all valid."""
    s = Screen.empty()
    # Don't set pf_mask
    if hasattr(s, 'pf_mask'):
        delattr(s, 'pf_mask')
    assert get_masked_keys(s) == []


def test_classify_attn_operational_assistant():
    """The success path: ATTN landed on Operational Assistant."""
    s = Screen.empty()
    s.rendered[0] = list("Operational Assistant Menu" + " " * 54)
    result = classify_attn_response(s)
    assert result == "OPER_ASSIST"


def test_classify_attn_system_request():
    s = Screen.empty()
    s.rendered[0] = list("System Request" + " " * 66)
    assert classify_attn_response(s) == "SYS_REQUEST"


def test_classify_attn_command_line_present():
    """If ===> is already there, F9 already worked (or wasn't needed)."""
    s = Screen.empty()
    s.rendered[19] = list("===>" + " " * 76)
    assert classify_attn_response(s) == "CMDLINE"


def test_classify_attn_blocked():
    """ATTN handler overridden — back to the same app screen."""
    s = Screen.empty()
    s.rendered[0] = list("Customer Inquiry" + " " * 64)
    assert classify_attn_response(s) == "BLOCKED"
