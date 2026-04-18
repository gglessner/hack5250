"""IBM i message-ID detection — the abend/oracle harvester.

Direct port of hack3270's ESMFingerprinter for the CPF/MCH/RNQ space.
"""
import pytest
from hack5250.attacks.detector import IBMiMessageDetector
from hack5250.tn5250 import TN5250
from hack5250.constants import ESC, CMD_WRITE_TO_DISPLAY, ORD_SF, ATTR_GREEN
from hackterm_core import EbcdicCodec
from tests.conftest import make_header


@pytest.fixture
def detector():
    return IBMiMessageDetector(TN5250())


@pytest.fixture
def codec():
    return EbcdicCodec()


def _screen_with(text: str, codec) -> bytes:
    """Build a minimal 5250 screen containing the given text."""
    body = bytes([ESC, CMD_WRITE_TO_DISPLAY, 0x00, 0x00, ORD_SF, ATTR_GREEN, 0x00, 0x50])
    body += codec.to_ebcdic(text)
    return make_header(len(body)) + body + b"\xff\xef"


def test_detects_mch1202(detector, codec, fake_daemon):
    detector.attach(fake_daemon)
    fake_daemon.fire_s2c(_screen_with("MCH1202 received by program at stmt 47", codec))
    assert "decimal_data_error" in detector.findings
    assert "MCH1202" in detector.findings["decimal_data_error"][0]


def test_detects_cpf1107_username_oracle(detector, codec, fake_daemon):
    detector.attach(fake_daemon)
    fake_daemon.fire_s2c(_screen_with("CPF1107 Password not correct for user", codec))
    assert "username_oracle" in detector.findings


def test_detects_cpf1120_username_oracle(detector, codec, fake_daemon):
    detector.attach(fake_daemon)
    fake_daemon.fire_s2c(_screen_with("CPF1120 User QSECOFR2 does not exist.", codec))
    assert "username_oracle" in detector.findings


def test_detects_cpd0078_dds_validation(detector, codec, fake_daemon):
    detector.attach(fake_daemon)
    fake_daemon.fire_s2c(_screen_with("CPD0078 Value 99 not allowed for OPTION", codec))
    assert "dds_validation_fired" in detector.findings


def test_detects_rnq_inquiry(detector, codec, fake_daemon):
    detector.attach(fake_daemon)
    fake_daemon.fire_s2c(_screen_with("RNQ1216 Error message CPF4131 appeared", codec))
    assert "rpg_inquiry" in detector.findings


def test_detects_display_program_messages(detector, codec, fake_daemon):
    detector.attach(fake_daemon)
    fake_daemon.fire_s2c(_screen_with("Display Program Messages", codec))
    assert "stack_trace_leak" in detector.findings


def test_extracts_program_from_stack_trace(detector, codec, fake_daemon):
    """When DSPPGMMSG fires, extract the program/library from the panel."""
    detector.attach(fake_daemon)
    fake_daemon.fire_s2c(_screen_with(
        "Display Program Messages   "
        "Program . . . . :   MCAD       "
        "Library . . . . :   MELSCARGO  ", codec))
    assert "leaked_programs" in detector.findings
    assert "MELSCARGO/MCAD" in detector.findings["leaked_programs"]


def test_ignores_c2s_traffic(detector, codec, fake_daemon):
    detector.attach(fake_daemon)
    fake_daemon.fire_c2s(_screen_with("MCH1202", codec))
    assert "decimal_data_error" not in detector.findings


def test_no_false_positive_on_normal_screen(detector, codec, fake_daemon):
    detector.attach(fake_daemon)
    fake_daemon.fire_s2c(_screen_with("Mels Cargo Main Menu", codec))
    assert detector.findings == {}


def test_multiple_detections_accumulate(detector, codec, fake_daemon):
    detector.attach(fake_daemon)
    fake_daemon.fire_s2c(_screen_with("MCH1202 first", codec))
    fake_daemon.fire_s2c(_screen_with("MCH1202 second", codec))
    assert len(detector.findings["decimal_data_error"]) == 2


# === E3: STRPCCMD canary (CVE-2005-0868) ===

from hack5250.attacks.detector import STRPCCMDCanary


@pytest.fixture
def canary():
    return STRPCCMDCanary()


def test_canary_detects_pco_structured_field(canary, fake_daemon):
    canary.attach(fake_daemon)
    pco = (b"\x00\x20\x12\xa0\x00\x00\x04\x00\x00\x03"  # 10-byte header
           + b"\x04\xf3\x00\x10\xd9\x21calc.exe\xff\xef")
    fake_daemon.fire_s2c(pco)
    assert len(canary.alerts) == 1
    assert "STRPCCMD" in canary.alerts[0]["warning"]
    assert "CVE-2005-0868" in canary.alerts[0]["warning"]


def test_canary_ignores_normal_screens(canary, fake_daemon, pkt_one_input_field):
    canary.attach(fake_daemon)
    fake_daemon.fire_s2c(pkt_one_input_field)
    assert canary.alerts == []


def test_canary_ignores_c2s(canary, fake_daemon):
    canary.attach(fake_daemon)
    fake_daemon.fire_c2s(b"\x04\xf3\x00\x10\xd9\x21payload")
    assert canary.alerts == []


def test_canary_captures_raw_hex(canary, fake_daemon):
    canary.attach(fake_daemon)
    pco = (b"\x00\x20\x12\xa0\x00\x00\x04\x00\x00\x03"
           + b"\x04\xf3\x00\x08\xd9\x21test\xff\xef")
    fake_daemon.fire_s2c(pco)
    assert "raw_hex" in canary.alerts[0]
    assert "04f3" in canary.alerts[0]["raw_hex"]
