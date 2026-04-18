"""
C3 — RPG state echo-back fuzzer.

Direct port of hack3270_libs/attacks/state_fuzz.py for 5250. RPG programs
stash state in hidden fields between EXFMTs (original keys, RRNs, auth
flags). Find hidden fields whose content appeared in earlier user input
→ that's the echo-back. Mutate it.

Three phases:
  RECORD  — observer captures (host_screen, user_input) pairs as Steps
  ANALYZE — find echo-back fields (step M input → step N>M output)
  MUTATE  — pure functions: length_plus_1, length_double, type_confusion,
            extra_sba (5250 row/col), step_swap

5250-specific: _split_inbound knows cursor-BEFORE-aid at HDR_LEN+0,1,2.
extra_sba uses 5250 row/col bytes. classify watches MCH/CPF/RNQ/RNX.
"""
import pytest
import sqlite3
from hack5250.tn5250 import TN5250
from hack5250.constants import HDR_LEN, ORD_SBA, AID_TABLE, IAC_EOR
from hackterm_core import Screen
from tests.conftest import make_header  # synthetic packet header builder


# === Synthetic 5250 packet builders for this module ===

_proto = TN5250()


def _screen_pkt(text: str) -> bytes:
    """Build a 5250 s2c packet that renders `text` and has one field
    whose content is the EBCDIC of `text`.

    Rather than hand-craft WTD orders, build a packet that parse() can
    read AND set Field.content. The simplest path: build it via
    conftest's pattern (SBA + SF + text bytes), then verify after."""
    from hack5250.constants import (
        ESC, CMD_WRITE_TO_DISPLAY, ORD_SBA, ORD_SF, ATTR_GREEN,
    )
    from tests.conftest import make_ffw
    ebcdic = _proto.codec.to_ebcdic(text)
    body = bytes([ESC, CMD_WRITE_TO_DISPLAY, 0x00, 0x00])
    body += bytes([ORD_SBA, 5, 10])
    body += bytes([ORD_SF]) + make_ffw() + bytes([ATTR_GREEN, 0x00, len(ebcdic)])
    body += ebcdic
    return make_header(len(body)) + body + IAC_EOR


def _input_pkt(text: str) -> bytes:
    """5250 inbound: HDR + cursor_row + cursor_col + AID + SBA + r + c + EBCDIC + IAC EOR."""
    ebcdic = _proto.codec.to_ebcdic(text)
    body = bytes([5, 10, AID_TABLE["ENTER"], ORD_SBA, 5, 10]) + ebcdic
    return make_header(len(body)) + body + IAC_EOR


@pytest.fixture
def fuzzer(tmp_path):
    from hack5250.attacks.differential import RPGStateFuzzer
    db = sqlite3.connect(str(tmp_path / "fuzz.db"))
    return RPGStateFuzzer(protocol=TN5250(), db=db)


# === Dataclasses (state_fuzz.py L41-64) ===

def test_step_dataclass():
    from hack5250.attacks.differential import Step
    s = Step(host_screen=Screen.empty(), user_input=b"\xf1", timestamp=0.0)
    assert s.user_input == b"\xf1"


def test_flow_dataclass():
    from hack5250.attacks.differential import Flow
    f = Flow(id=0, name="login", steps=[])
    assert f.name == "login"
    assert f.steps == []


def test_echotarget_dataclass():
    from hack5250.attacks.differential import EchoTarget
    t = EchoTarget(step_idx=2, field_idx=0, source_step=0, confidence=1.0)
    assert t.confidence == 1.0


# === Recording (state_fuzz.py L108-170) ===

def test_recorder_starts_not_recording(fuzzer):
    assert fuzzer.recording is False


def test_record_s2c_creates_step(fuzzer, fake_daemon):
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("test")
    fake_daemon.fire_s2c(_screen_pkt("ENTER USERID"))
    assert len(fuzzer.current_flow.steps) == 1


def test_record_c2s_attaches_to_previous_step(fuzzer, fake_daemon):
    """c2s goes on the PREVIOUS step (the screen the user responded to)."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("test")
    fake_daemon.fire_s2c(_screen_pkt("ENTER USERID"))
    pkt = _input_pkt("BOB")
    fake_daemon.fire_c2s(pkt)
    assert fuzzer.current_flow.steps[0].user_input == pkt


def test_record_c2s_before_screen_dropped(fuzzer, fake_daemon):
    """Recording started mid-conversation: c2s with no step → drop silently."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("mid")
    fake_daemon.fire_c2s(_input_pkt("ORPHAN"))
    assert len(fuzzer.current_flow.steps) == 0


def test_stop_recording_persists(fuzzer, fake_daemon):
    """Flows + Steps tables. Same schema as hack3270's state_fuzz."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("login")
    fake_daemon.fire_s2c(_screen_pkt("USERID:"))
    fake_daemon.fire_c2s(_input_pkt("BOB"))
    flow_id = fuzzer.stop_recording()
    assert flow_id > 0
    cur = fuzzer.db.cursor()
    cur.execute("SELECT name FROM Flows WHERE id = ?", (flow_id,))
    assert cur.fetchone()[0] == "login"


def test_load_flow_roundtrip(fuzzer, fake_daemon):
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("rt")
    fake_daemon.fire_s2c(_screen_pkt("HELLO"))
    fake_daemon.fire_c2s(_input_pkt("WORLD"))
    flow_id = fuzzer.stop_recording()
    loaded = fuzzer.load_flow(flow_id)
    assert loaded.name == "rt"
    assert len(loaded.steps) == 1
    assert loaded.steps[0].user_input == _input_pkt("WORLD")


# === _split_inbound — THE 5250-SPECIFIC ADAPTATION ===

def test_split_inbound_5250_layout():
    """5250 inbound: HDR(10) + cursor_row(1) + cursor_col(1) + AID(1) + SBA + ...

    header = HDR + cursor + AID + SBA + row + col  (everything before data)
    data   = EBCDIC field bytes
    trailer= IAC EOR

    This is the load-bearing 5250 difference. 3270 has no 10-byte HDR
    and AID comes BEFORE cursor."""
    from hack5250.attacks.differential import _split_inbound
    pkt = _input_pkt("ABC")  # HDR + 5 + 10 + ENTER + SBA + 5 + 10 + C1 C2 C3 + IAC EOR
    h, d, t = _split_inbound(pkt)
    assert d == b"\xc1\xc2\xc3"  # 'ABC' EBCDIC
    assert t == IAC_EOR
    # Header includes everything up to and incl SBA+row+col
    assert h[-3] == ORD_SBA
    assert h[-2] == 5
    assert h[-1] == 10
    # Reassembly is identity
    assert h + d + t == pkt


def test_split_inbound_no_sba():
    """AID-only packet (CLEAR/PA1) — no SBA. Header is HDR+cursor+AID."""
    from hack5250.attacks.differential import _split_inbound
    body = bytes([1, 1, AID_TABLE["CLEAR"]])  # cursor + AID, no SBA
    pkt = make_header(len(body)) + body + IAC_EOR
    h, d, t = _split_inbound(pkt)
    assert d == b""
    assert len(h) == HDR_LEN + 3  # HDR + cursor(2) + AID(1)
    assert t == IAC_EOR


# === Mutations (state_fuzz.py L416-462, adapted) ===

def test_mutate_length_plus_1():
    from hack5250.attacks.differential import mutate_input
    original = _input_pkt("ABC")
    out = mutate_input(original, "length_plus_1")
    assert len(out) == len(original) + 1
    assert out.endswith(IAC_EOR)
    assert b"\xc1\xc2\xc3" in out


def test_mutate_length_double():
    from hack5250.attacks.differential import mutate_input
    original = _input_pkt("ABC")
    out = mutate_input(original, "length_double")
    assert b"\xc1\xc2\xc3\xc1\xc2\xc3" in out


def test_mutate_type_confusion_numeric_to_alpha():
    from hack5250.attacks.differential import mutate_input
    original = _input_pkt("123")  # F1 F2 F3 EBCDIC
    out = mutate_input(original, "type_confusion")
    assert b"\xf1\xf2\xf3" not in out
    h, d, t = out[:-5], out[-5:-2], out[-2:]
    # Data bytes now in alpha range C1-E9
    _, data, _ = _split_inbound_helper(out)
    assert all(0xC1 <= b <= 0xE9 for b in data)


def _split_inbound_helper(pkt):
    """Local re-import to avoid the chicken-and-egg of testing _split_inbound."""
    from hack5250.attacks.differential import _split_inbound
    return _split_inbound(pkt)


def test_mutate_extra_sba_5250_addressing():
    """5250 SBA is [0x11][row:1][col:1] — NOT 3270's 12-bit encoded.

    The phantom field goes at row 24 col 60 (off-page-ish), payload
    'HACK' = C8 C1 C3 D2 EBCDIC."""
    from hack5250.attacks.differential import mutate_input
    original = _input_pkt("AB")
    out = mutate_input(original, "extra_sba")
    # Two SBA orders now: original + phantom
    body = out[HDR_LEN:-2]
    sba_count = sum(1 for i in range(3, len(body)-2)
                    if body[i] == ORD_SBA and body[i+1] <= 24)
    assert sba_count >= 2
    # Phantom payload present
    assert b"\xc8\xc1\xc3\xd2" in out


def test_mutate_step_swap():
    from hack5250.attacks.differential import mutate_input
    a = _input_pkt("AAA")
    b = _input_pkt("ZZZ")
    assert mutate_input(a, "step_swap", swap_with=b) == b


# === classify_result — IBM i message IDs ===

def test_classify_abend_mch1202():
    """MCH1202 = decimal data error — packed/zoned got non-numeric.
    The 5250 equivalent of 3270's ASRA."""
    from hack5250.attacks.differential import classify_result
    expected = _proto.parse(_screen_pkt("X"))
    actual = _screen_pkt("MCH1202 Decimal data error")
    assert classify_result(actual, expected, _proto) == "ABEND"


def test_classify_abend_cpf():
    from hack5250.attacks.differential import classify_result
    expected = _proto.parse(_screen_pkt("X"))
    actual = _screen_pkt("CPF5068 Subfile not active")
    assert classify_result(actual, expected, _proto) == "ABEND"


def test_classify_abend_rnq():
    """RNQ = RPG inquiry message. Program hit unexpected condition."""
    from hack5250.attacks.differential import classify_result
    expected = _proto.parse(_screen_pkt("X"))
    actual = _screen_pkt("RNQ1218 Unable to allocate record")
    assert classify_result(actual, expected, _proto) == "ABEND"


def test_classify_disconnect():
    from hack5250.attacks.differential import classify_result
    expected = _proto.parse(_screen_pkt("X"))
    assert classify_result(None, expected, _proto) == "DISCONNECT"
    assert classify_result(b"", expected, _proto) == "DISCONNECT"


# === screens_match_fuzzy (state_fuzz.py L509-532, COPY VERBATIM) ===

def test_screens_match_fuzzy_same_structure():
    from hack5250.attacks.differential import screens_match_fuzzy
    a = pytest.mk_screen([pytest.mk_field(5, 10, 8, protected=True)])
    b = pytest.mk_screen([pytest.mk_field(5, 10, 8, protected=True)])
    assert screens_match_fuzzy(a, b) is True


def test_screens_match_fuzzy_different_count():
    from hack5250.attacks.differential import screens_match_fuzzy
    a = pytest.mk_screen([pytest.mk_field(5, 10, 8)])
    b = pytest.mk_screen([pytest.mk_field(5, 10, 8), pytest.mk_field(7, 1, 4)])
    assert screens_match_fuzzy(a, b) is False
