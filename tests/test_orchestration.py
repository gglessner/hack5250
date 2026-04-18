"""
Tests for Hack5250 orchestration.

These verify wiring — that toggles map to the right daemon opts, that
the intercept callback consumes packets, that send_aid builds correct
5250 inbound bytes. They do NOT open real sockets; daemon.server is
stubbed where needed.

What CAN'T be tested without a live host:
  - The full negotiate→handshake→mutate flow (needs a real IBM i)
  - IBMRSEED stripping captures real creds
  - ATTN escape actually reaches Operational Assistant
"""
import json
import pytest

from hack5250.libhack5250 import Hack5250, DEFAULT_PROXY_PORT, DEFAULT_API_PORT
from hack5250.constants import AID_TABLE, HDR_LEN, HDR_FLAG_ATN, IAC_EOR
from hackterm_core import Screen


# --- Fixtures ---------------------------------------------------------

@pytest.fixture
def h(tmp_path, monkeypatch):
    """A Hack5250 instance with its db file in tmp_path. No sockets bound."""
    monkeypatch.chdir(tmp_path)
    inst = Hack5250("127.0.0.1", 23, project_name="test_orch")
    yield inst
    inst.shutdown()


class FakeSocket:
    """Captures bytes passed to .send() so we can assert on packet structure
    without a real host."""
    def __init__(self):
        self.sent = []

    def send(self, data):
        self.sent.append(data)
        return len(data)

    def close(self):
        pass


@pytest.fixture
def h_connected(h):
    """h with a fake server socket so inject_to_server works."""
    h.daemon.server = FakeSocket()
    return h


# --- Construction -----------------------------------------------------

def test_constructs_with_defaults(h):
    assert h.protocol.name == "tn5250"
    assert h.daemon is not None
    assert h.storage is not None
    assert h.injector is not None
    assert h.api is not None


def test_codec_is_protocol_codec(h):
    """codec attr is a ref to the protocol's codec, not a duplicate."""
    assert h.codec is h.protocol.codec


def test_captured_creds_is_protocol_ref(h):
    """captured_creds is a live ref — protocol appends, GUI sees it."""
    assert h.captured_creds is h.protocol.captured_creds
    h.protocol.captured_creds.append(("QSECOFR", "PASSWORD"))
    assert h.captured_creds == [("QSECOFR", "PASSWORD")]


def test_default_ports():
    """5250+1 mnemonic; distinct from hack3270's 3271/31337."""
    assert DEFAULT_PROXY_PORT == 5251
    assert DEFAULT_API_PORT == 52500


def test_db_file_created(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    h = Hack5250("10.0.0.50", 23, project_name="myproj")
    try:
        assert (tmp_path / "myproj.db").exists()
    finally:
        h.shutdown()


def test_codepage_passed_to_protocol(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    h = Hack5250("127.0.0.1", 23, project_name="cp", codepage="cp500")
    try:
        # cp500 differs from cp037 at '!' — quick sanity check
        assert h.codec.codepage == "cp500"
    finally:
        h.shutdown()


# --- Mutate-opts toggles ----------------------------------------------

def test_ffw_unprotect_maps_to_mutate_opts(h):
    assert h.daemon.mutate_opts.unprotect is False
    h.set_ffw_unprotect(True)
    assert h.daemon.mutate_opts.unprotect is True
    h.set_ffw_unprotect(False)
    assert h.daemon.mutate_opts.unprotect is False


def test_ffw_reveal_hidden_maps_to_mutate_opts(h):
    h.set_ffw_reveal_hidden(True)
    assert h.daemon.mutate_opts.reveal_hidden is True


def test_ffw_remove_numeric_maps_to_mutate_opts(h):
    h.set_ffw_remove_numeric(True)
    assert h.daemon.mutate_opts.remove_numeric is True


def test_ffw_high_visibility_maps_to_mutate_opts(h):
    h.set_ffw_high_visibility(True)
    assert h.daemon.mutate_opts.high_visibility is True


# --- Negotiate-opts toggles -------------------------------------------

def test_ibmrseed_downgrade_maps_to_negotiate_opts(h):
    assert h.daemon.negotiate_opts.force_cleartext is False
    h.set_ibmrseed_downgrade(True)
    assert h.daemon.negotiate_opts.force_cleartext is True


def test_devname_spoof_maps_to_negotiate_opts(h):
    assert h.daemon.negotiate_opts.spoof_device_name is None
    h.set_devname_spoof("DSP01")
    assert h.daemon.negotiate_opts.spoof_device_name == "DSP01"
    h.set_devname_spoof(None)
    assert h.daemon.negotiate_opts.spoof_device_name is None


# --- AID injection ----------------------------------------------------

def test_send_aid_builds_correct_packet(h_connected):
    """5250 inbound: [HDR(10)] cursor_row cursor_col AID [no fields] IAC EOR"""
    h_connected.send_aid("ENTER")
    sent = h_connected.daemon.server.sent
    assert len(sent) == 1
    pkt = sent[0]
    # body offset = HDR_LEN; body = row(1) + col(1) + AID; then IAC EOR
    assert pkt[HDR_LEN]     == 1                   # cursor row
    assert pkt[HDR_LEN + 1] == 1                   # cursor col
    assert pkt[HDR_LEN + 2] == AID_TABLE["ENTER"]  # 0xF1
    assert pkt.endswith(IAC_EOR)


def test_send_aid_unknown_key_raises(h_connected):
    with pytest.raises(KeyError):
        h_connected.send_aid("F99")


def test_send_attn_uses_header_flag_not_aid(h_connected):
    """ATTN is bit 0x40 in header byte 7 (corrected 2026-04-08 — flags
    are 16-bit at offsets 7-8, not 6-7)."""
    h_connected.send_attn()
    pkt = h_connected.daemon.server.sent[0]
    assert pkt[7] & HDR_FLAG_ATN
    # No AID body — just header + IAC EOR
    assert len(pkt) == HDR_LEN + len(IAC_EOR)


# --- Mask-capture intercept -------------------------------------------

def test_mask_intercept_consumes_packet_when_armed(h):
    """When armed, the intercept returns None (drop) and disarms itself."""
    h.arm_mask_capture()
    assert h._capture_armed is True

    # Build a packet containing '*****' in EBCDIC (cp037: '*' = 0x5C)
    star = h.codec.to_ebcdic("*")[0]
    pkt = b"\x00\x10\x12\xa0\x00\x04\x00\x00\x03\x00" + bytes([star] * 5) + b"\xff\xef"

    result = h.daemon._client_intercept(pkt)
    assert result is None                   # consumed — not forwarded
    assert h._capture_armed is False        # one-shot
    assert h.injector.mask_len == 5         # captured the run


def test_mask_intercept_passthrough_when_disarmed(h):
    """Default state: intercept passes data through unchanged."""
    pkt = b"\x00\x0c\x12\xa0\x00\x04\x00\x00\x03\x00\xff\xef"
    result = h.daemon._client_intercept(pkt)
    assert result is pkt   # exact same object


def test_is_mask_ready(h):
    assert h.is_mask_ready() is False
    h.arm_mask_capture()
    star = h.codec.to_ebcdic("*")[0]
    h.daemon._client_intercept(b"\x00" * 10 + bytes([star] * 3) + b"\xff\xef")
    assert h.is_mask_ready() is True


# --- Screen observer --------------------------------------------------

def test_observer_parses_s2c_traffic(h, pkt_one_input_field):
    """The s2c observer should parse and stash the screen."""
    assert h.last_screen is None
    # Manually fire the observer (no real socket)
    obs = h.daemon._observers[0]
    obs(pkt_one_input_field, "s2c")
    assert h.last_screen is not None
    assert len(h.last_screen.fields) == 1


def test_observer_ignores_c2s_traffic(h, pkt_one_input_field):
    obs = h.daemon._observers[0]
    obs(pkt_one_input_field, "c2s")
    assert h.last_screen is None


# --- Masked-keys passthrough ------------------------------------------

def test_get_masked_keys_empty_before_screen(h):
    assert h.get_masked_keys() == []


def test_get_masked_keys_after_soh_screen(h, pkt_with_soh):
    """pkt_with_soh enables only F3 + F12 — everything else is masked."""
    obs = h.daemon._observers[0]
    obs(pkt_with_soh, "s2c")
    masked = h.get_masked_keys()
    assert "F3" not in masked
    assert "F12" not in masked
    assert "F1" in masked
    assert "F24" in masked


# --- API handlers -----------------------------------------------------

def test_api_ping_handler(h):
    assert h.api._handlers["ping"]("") == "pong"


def test_api_get_screen_text_empty_before_screen(h):
    assert h.api._handlers["get_screen_text"]("") == ""


def test_api_get_captured_creds_json(h):
    h.protocol.captured_creds.append(("ALICE", "secret"))
    out = h.api._handlers["get_captured_creds"]("")
    assert json.loads(out) == [["ALICE", "secret"]]


def test_api_send_aid_returns_ok(h_connected):
    out = h_connected.api._handlers["send_aid"]("F3")
    assert out == "OK"
    pkt = h_connected.daemon.server.sent[0]
    assert pkt[HDR_LEN + 2] == AID_TABLE["F3"]


# --- Lifecycle --------------------------------------------------------

def test_tick_noop_when_disconnected(h):
    """tick() must not raise when no sockets are connected."""
    h.tick()  # should be a no-op
