import pytest
from hack5250.tn5250 import TN5250
from hack5250.constants import (
    FFW_BYPASS, FFW_SHIFT_MASK, FFW_MAND_ENTRY, FFW_FER,
    ATTR_NONDISP, ATTR_GREEN, ATTR_WHITE,
)
from hackterm_core import MutateOpts


@pytest.fixture
def proto():
    return TN5250()


def test_mutate_no_opts_is_passthrough(proto, pkt_protected_field):
    """All toggles off → bytes unchanged."""
    out = proto.mutate(pkt_protected_field, MutateOpts())
    assert out == pkt_protected_field


def test_mutate_unprotect_clears_bypass_bit_on_hidden_field(proto, pkt_hidden_field):
    """The FFW bypass attack — fires on protected+hidden fields.

    Live finding 2026-04-08: unconditional unprotect cleared BYPASS on
    97 visible-protected fields, breaking the format table. Now selective:
    only fires when the field is also NONDISP (the actual attack target)."""
    # pkt_hidden_field has FFW (no bypass) + ATTR_NONDISP. Need bypass set.
    # Use the conftest builder to make a hidden+protected packet inline.
    from tests.conftest import make_header, make_ffw
    from hack5250.constants import ESC, CMD_WRITE_TO_DISPLAY, ORD_SBA, ORD_SF, ATTR_NONDISP
    body = bytes([ESC, CMD_WRITE_TO_DISPLAY, 0x00, 0x00, ORD_SBA, 3, 5,
                  ORD_SF]) + make_ffw(bypass=True) + bytes([ATTR_NONDISP, 0x00, 0x0C])
    pkt = make_header(len(body)) + body + b"\xff\xef"

    out = proto.mutate(pkt, MutateOpts(unprotect=True))
    s = proto.parse(out)
    assert s.fields[0].protected is False


def test_mutate_unprotect_only_changes_ffw(proto):
    """Verify mutation is surgical — packet length unchanged, only FFW high byte differs."""
    from tests.conftest import make_header, make_ffw
    from hack5250.constants import ESC, CMD_WRITE_TO_DISPLAY, ORD_SBA, ORD_SF, ATTR_NONDISP
    body = bytes([ESC, CMD_WRITE_TO_DISPLAY, 0x00, 0x00, ORD_SBA, 1, 1,
                  ORD_SF]) + make_ffw(bypass=True) + bytes([ATTR_NONDISP, 0x00, 0x10])
    pkt = make_header(len(body)) + body + b"\xff\xef"

    out = proto.mutate(pkt, MutateOpts(unprotect=True))
    assert len(out) == len(pkt)
    diffs = [(i, a, b) for i, (a, b) in enumerate(zip(pkt, out)) if a != b]
    # Exactly one byte changed (the high byte of FFW where BYPASS lives)
    assert len(diffs) == 1
    idx, before, after = diffs[0]
    # BYPASS is bit 0x20 in the high byte (0x2000 >> 8)
    assert (before & 0x20) == 0x20  # was set
    assert (after & 0x20) == 0x00   # now clear


def test_mutate_unprotect_skips_visible_protected(proto, pkt_protected_field):
    """Visible protected field (ATTR_GREEN) is decorative output —
    making it a tab stop breaks the format table. Leave it alone."""
    out = proto.mutate(pkt_protected_field, MutateOpts(unprotect=True))
    assert out == pkt_protected_field


def test_mutate_unprotect_leaves_unprotected_alone(proto, pkt_one_input_field):
    """Already-unprotected fields don't change."""
    out = proto.mutate(pkt_one_input_field, MutateOpts(unprotect=True))
    assert out == pkt_one_input_field


def test_mutate_reveal_hidden_rewrites_nondisp(proto, pkt_hidden_field):
    out = proto.mutate(pkt_hidden_field, MutateOpts(reveal_hidden=True))
    s = proto.parse(out)
    assert s.fields[0].hidden is False


def test_mutate_reveal_hidden_uses_green_by_default(proto, pkt_hidden_field):
    """Without high_visibility, NONDISP → GREEN."""
    out = proto.mutate(pkt_hidden_field, MutateOpts(reveal_hidden=True))
    # Find where ATTR_NONDISP was, verify it's now ATTR_GREEN
    idx = pkt_hidden_field.index(ATTR_NONDISP)
    assert out[idx] == ATTR_GREEN


def test_mutate_reveal_hidden_with_high_vis_uses_white(proto, pkt_hidden_field):
    """high_visibility → NONDISP becomes WHITE for emphasis."""
    out = proto.mutate(pkt_hidden_field, MutateOpts(reveal_hidden=True, high_visibility=True))
    idx = pkt_hidden_field.index(ATTR_NONDISP)
    assert out[idx] == ATTR_WHITE


def test_mutate_remove_numeric_clears_shift_bits(proto, pkt_numeric_field):
    out = proto.mutate(pkt_numeric_field, MutateOpts(remove_numeric=True))
    s = proto.parse(out)
    assert s.fields[0].numeric is False


def test_mutate_remove_numeric_also_clears_mand_and_fer(proto):
    """When fuzzing, mandatory-entry and field-exit-required are obstacles.
    remove_numeric clears them too."""
    from hack5250.constants import ESC, CMD_WRITE_TO_DISPLAY, ORD_SBA, ORD_SF, ATTR_GREEN, FFW_ID
    from tests.conftest import make_header

    # FFW with numeric + mandatory + FER
    ffw = FFW_ID | 0x0300 | FFW_MAND_ENTRY | FFW_FER
    body = bytes([ESC, CMD_WRITE_TO_DISPLAY, 0x00, 0x00, ORD_SBA, 1, 1, ORD_SF])
    body += bytes([(ffw >> 8) & 0xFF, ffw & 0xFF, ATTR_GREEN, 0x00, 0x05])
    pkt = make_header(len(body) + 2) + body + bytes([0xFF, 0xEF])

    out = TN5250().mutate(pkt, MutateOpts(remove_numeric=True))
    # Find FFW in output, verify all three are clear
    ffw_idx = body.index(ORD_SF) + 1 + 10  # +10 for header offset
    out_ffw = (out[ffw_idx] << 8) | out[ffw_idx + 1]
    assert (out_ffw & FFW_SHIFT_MASK) == 0
    assert (out_ffw & FFW_MAND_ENTRY) == 0
    assert (out_ffw & FFW_FER) == 0


def test_mutate_does_not_touch_soh(proto, pkt_with_soh):
    """SOH PF-mask rewrite REMOVED — caused X-SYSTEM lock on Java emulator
    (live finding 2026-04-08). The mask is still READABLE via parse() for
    the get_masked_keys analysis; we just don't WRITE it. Sending masked
    AIDs still works — the host's mask is advisory, not enforced."""
    out = proto.mutate(pkt_with_soh, MutateOpts(unprotect=True))
    s = proto.parse(out)
    # pf_mask UNCHANGED from what the host sent (F3+F12 = 0x201000)
    assert s.pf_mask == 0x201000


def test_mutate_combo_all_toggles(proto, pkt_signon_screen):
    """All toggles together on the realistic signon screen."""
    opts = MutateOpts(unprotect=True, reveal_hidden=True,
                      remove_numeric=True, high_visibility=True)
    out = proto.mutate(pkt_signon_screen, opts)
    s = proto.parse(out)
    # Password field should no longer be hidden
    password = next(f for f in s.fields if f.row == 7)
    assert password.hidden is False


def test_mutate_skips_transparent_data(proto):
    """TD (Transparent Data) blocks must NOT be parsed/mutated.
    A 0x1D byte inside a TD block is data, not SF."""
    from hack5250.constants import ESC, CMD_WRITE_TO_DISPLAY, ORD_TD, ORD_SF, ATTR_NONDISP
    from tests.conftest import make_header

    # TD containing what LOOKS like SF + NONDISP
    td_payload = bytes([ORD_SF, 0x40, 0x00, ATTR_NONDISP, 0x00, 0x05])
    body = bytes([ESC, CMD_WRITE_TO_DISPLAY, 0x00, 0x00])
    body += bytes([ORD_TD, 0x00, len(td_payload)]) + td_payload
    pkt = make_header(len(body) + 2) + body + bytes([0xFF, 0xEF])

    out = TN5250().mutate(pkt, MutateOpts(reveal_hidden=True))
    # The NONDISP byte inside TD must be UNCHANGED
    assert ATTR_NONDISP in out
    assert out == pkt  # nothing should have changed


def test_mutate_preserves_length(proto, pkt_signon_screen):
    """5250 mutate never changes packet length (unlike 3270's high_visibility
    which injects extra SFE bytes). All mutations are byte-for-byte rewrites."""
    out = proto.mutate(pkt_signon_screen, MutateOpts(unprotect=True, reveal_hidden=True))
    assert len(out) == len(pkt_signon_screen)


# === E1: Self-check FCW strip ===

def test_mutate_strips_selfcheck_mod10(proto):
    """FCW 0xB1A0 (Luhn) → replaced with 0x8000 (no-op FCW).
    Terminal-side validation removed; if host trusts terminal,
    invalid check digits persist."""
    from hack5250.constants import (
        ESC, CMD_WRITE_TO_DISPLAY, ORD_SBA, ORD_SF, ATTR_GREEN,
        FCW_SELFCHECK_MOD10, FCW_NOOP,
    )
    from tests.conftest import make_header, make_ffw

    body = bytes([ESC, CMD_WRITE_TO_DISPLAY, 0x00, 0x00, ORD_SBA, 5, 5, ORD_SF])
    body += make_ffw()  # plain input field
    body += bytes([(FCW_SELFCHECK_MOD10 >> 8) & 0xFF, FCW_SELFCHECK_MOD10 & 0xFF])
    body += bytes([ATTR_GREEN, 0x00, 0x10])  # attr + len=16 (account number)
    pkt = make_header(len(body)) + body + b"\xff\xef"

    out = proto.mutate(pkt, MutateOpts(remove_numeric=True))
    assert len(out) == len(pkt)  # length unchanged — replace not delete
    # FCW position: header(10) + body offset of SF + 1 (skip SF) + 2 (skip FFW)
    sf_idx = 10 + body.index(ORD_SF)
    fcw_pos = sf_idx + 1 + 2
    assert out[fcw_pos:fcw_pos+2] == bytes([(FCW_NOOP >> 8) & 0xFF, FCW_NOOP & 0xFF])


def test_mutate_strips_selfcheck_mod11(proto):
    """FCW 0xB140 (mod-11) → also replaced."""
    from hack5250.constants import (
        ESC, CMD_WRITE_TO_DISPLAY, ORD_SBA, ORD_SF, ATTR_GREEN,
        FCW_SELFCHECK_MOD11, FCW_NOOP,
    )
    from tests.conftest import make_header, make_ffw

    body = bytes([ESC, CMD_WRITE_TO_DISPLAY, 0x00, 0x00, ORD_SBA, 5, 5, ORD_SF])
    body += make_ffw()
    body += bytes([(FCW_SELFCHECK_MOD11 >> 8) & 0xFF, FCW_SELFCHECK_MOD11 & 0xFF])
    body += bytes([ATTR_GREEN, 0x00, 0x10])
    pkt = make_header(len(body)) + body + b"\xff\xef"

    out = proto.mutate(pkt, MutateOpts(remove_numeric=True))
    sf_idx = 10 + body.index(ORD_SF)
    fcw_pos = sf_idx + 1 + 2
    out_fcw = (out[fcw_pos] << 8) | out[fcw_pos+1]
    assert out_fcw == FCW_NOOP


def test_mutate_leaves_other_fcw_types_alone(proto):
    """Non-self-check FCWs (e.g. 0x8801 cursor-progression) untouched."""
    from hack5250.constants import (
        ESC, CMD_WRITE_TO_DISPLAY, ORD_SBA, ORD_SF, ATTR_GREEN,
    )
    from tests.conftest import make_header, make_ffw

    OTHER_FCW = 0x8801
    body = bytes([ESC, CMD_WRITE_TO_DISPLAY, 0x00, 0x00, ORD_SBA, 5, 5, ORD_SF])
    body += make_ffw()
    body += bytes([(OTHER_FCW >> 8) & 0xFF, OTHER_FCW & 0xFF])
    body += bytes([ATTR_GREEN, 0x00, 0x10])
    pkt = make_header(len(body)) + body + b"\xff\xef"

    out = proto.mutate(pkt, MutateOpts(remove_numeric=True))
    sf_idx = 10 + body.index(ORD_SF)
    fcw_pos = sf_idx + 1 + 2
    # Unchanged
    assert (out[fcw_pos] << 8) | out[fcw_pos+1] == OTHER_FCW


# === E2: Write Error Code suppression ===

def test_mutate_suppresses_error_text(proto):
    """CMD_WRITE_ERROR_CODE (0x21) text blanked when suppress_errors=True.
    Operator's message line shows spaces instead of 'Password not correct'.
    Length unchanged — we blank, not delete."""
    from hack5250.constants import ESC, CMD_WRITE_ERROR_CODE
    from hackterm_core import EbcdicCodec
    from tests.conftest import make_header

    codec = EbcdicCodec()
    error_text = codec.to_ebcdic("Password not correct for user profile.")
    body = bytes([ESC, CMD_WRITE_ERROR_CODE]) + error_text
    pkt = make_header(len(body)) + body + b"\xff\xef"

    proto.suppress_errors = True
    out = proto.mutate(pkt, MutateOpts())  # no MutateOpts needed — instance flag

    assert len(out) == len(pkt)
    # Error text replaced with EBCDIC spaces
    text_start = 10 + 2  # header(10) + ESC + CMD
    text_end = len(out) - 2  # before IAC EOR
    assert out[text_start:text_end] == b"\x40" * len(error_text)
    assert error_text not in out


def test_mutate_error_passthrough_when_suppress_off(proto):
    """suppress_errors=False (default) → error text unchanged."""
    from hack5250.constants import ESC, CMD_WRITE_ERROR_CODE
    from hackterm_core import EbcdicCodec
    from tests.conftest import make_header

    codec = EbcdicCodec()
    error_text = codec.to_ebcdic("INVALID SUPERVISOR CODE")
    body = bytes([ESC, CMD_WRITE_ERROR_CODE]) + error_text
    pkt = make_header(len(body)) + body + b"\xff\xef"

    out = proto.mutate(pkt, MutateOpts())  # suppress_errors defaults False
    assert out == pkt


def test_mutate_error_suppress_only_blanks_error_cmd(proto, pkt_one_input_field):
    """A WTD packet with no error command is unaffected by suppress_errors."""
    proto.suppress_errors = True
    out = proto.mutate(pkt_one_input_field, MutateOpts())
    assert out == pkt_one_input_field
