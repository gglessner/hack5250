import pytest
from hack5250.tn5250 import TN5250
from hack5250.constants import USERVAR_IBMRSEED, USERVAR_DEVNAME, NE_USERVAR
from hackterm_core import NegotiateOpts


@pytest.fixture
def proto():
    return TN5250()


def test_negotiate_passthrough_when_opts_off(proto, ibmrseed_offer):
    """No opts → bytes unchanged."""
    out = proto.negotiate_hook(ibmrseed_offer, "s2c", NegotiateOpts())
    assert out == ibmrseed_offer


def test_force_cleartext_strips_seed(proto, ibmrseed_offer):
    """The IBMRSEED downgrade. Strip the 8-byte seed → client falls back
    to cleartext password per RFC 2877 §5."""
    out = proto.negotiate_hook(ibmrseed_offer, "s2c",
                               NegotiateOpts(force_cleartext=True))
    # IBMRSEED USERVAR name should still be present
    assert USERVAR_IBMRSEED in out
    # But the seed bytes (01 02 03 04 05 06 07 08) should be gone
    assert b"\x01\x02\x03\x04\x05\x06\x07\x08" not in out
    # Output is shorter by exactly 8 bytes
    assert len(out) == len(ibmrseed_offer) - 8


def test_force_cleartext_records_stripped_seed(proto, ibmrseed_offer):
    """Proxy remembers the seed for forensics/findings."""
    proto.negotiate_hook(ibmrseed_offer, "s2c",
                         NegotiateOpts(force_cleartext=True))
    assert proto._stripped_seed == b"\x01\x02\x03\x04\x05\x06\x07\x08"


def test_force_cleartext_only_on_s2c(proto, ibmrseed_offer):
    """Don't strip on c2s direction (that's the client's response)."""
    out = proto.negotiate_hook(ibmrseed_offer, "c2s",
                               NegotiateOpts(force_cleartext=True))
    assert out == ibmrseed_offer


def test_force_cleartext_no_seed_present(proto):
    """If IBMRSEED isn't in the data, do nothing."""
    data = bytes([0xFF, 0xFA, 0x27, 0x01, 0x03]) + b"DEVNAME" + bytes([0xFF, 0xF0])
    out = proto.negotiate_hook(data, "s2c", NegotiateOpts(force_cleartext=True))
    assert out == data


def test_capture_cleartext_password(proto, cleartext_password_response):
    """After stripping the seed, watch for IBMSUBSPW on c2s.
    The fixture has USER=QSECOFR, IBMSUBSPW=PASSWORD."""
    # Simulate having stripped the seed
    proto._stripped_seed = b"\x00" * 8
    proto.negotiate_hook(cleartext_password_response, "c2s",
                         NegotiateOpts(force_cleartext=True))
    assert ("QSECOFR", "PASSWORD") in proto.captured_creds


def test_capture_only_when_seed_was_stripped(proto, cleartext_password_response):
    """Don't claim credit for credentials if we didn't strip the seed
    (maybe the client just doesn't support encryption)."""
    proto._stripped_seed = None
    proto.negotiate_hook(cleartext_password_response, "c2s",
                         NegotiateOpts(force_cleartext=True))
    assert proto.captured_creds == []


def test_devname_spoof_rewrites_value(proto):
    """DEVNAME spoofing — analog of 3270 LU-name spoof."""
    # Client sending: USERVAR DEVNAME VALUE QPADEV0001
    data = (bytes([0xFF, 0xFA, 0x27, 0x00, NE_USERVAR]) + USERVAR_DEVNAME +
            bytes([0x01]) + b"QPADEV0001" + bytes([0xFF, 0xF0]))
    out = proto.negotiate_hook(data, "c2s",
                               NegotiateOpts(spoof_device_name="DSP01"))
    assert b"DSP01" in out
    assert b"QPADEV0001" not in out


def test_devname_spoof_only_on_c2s(proto):
    data = (bytes([0xFF, 0xFA, 0x27, 0x00, NE_USERVAR]) + USERVAR_DEVNAME +
            bytes([0x01]) + b"QPADEV0001" + bytes([0xFF, 0xF0]))
    out = proto.negotiate_hook(data, "s2c",
                               NegotiateOpts(spoof_device_name="DSP01"))
    assert out == data  # unchanged on s2c


def test_detect_new_environ(proto):
    """detect() recognizes IAC DO NEW-ENVIRON as 5250."""
    assert proto.detect(bytes([0xFF, 0xFD, 0x27])) is True


def test_detect_terminal_type(proto):
    """detect() recognizes IBM-3179-2 terminal type."""
    assert proto.detect(b"...IBM-3179-2...") is True


def test_detect_rejects_3270(proto):
    """3270 uses option 0x28 (TN3270E), not 0x27."""
    assert proto.detect(bytes([0xFF, 0xFD, 0x28])) is False
    assert proto.detect(b"IBM-3278-2-E") is False


# === Phase 3 A2: IBMPROGRAM/IBMIMENU/IBMCURLIB injection ===================

@pytest.fixture
def c2s_environ():
    """Generic client→server NEW-ENVIRON IS packet.
    IAC SB NEW-ENVIRON IS USERVAR "USER" VALUE "ALICE" IAC SE
    Just enough structure to have an IAC SE terminator to splice before."""
    return (bytes([0xFF, 0xFA, 0x27, 0x00]) +
            bytes([NE_USERVAR]) + b"USER" + bytes([0x01]) + b"ALICE" +
            bytes([0xFF, 0xF0]))


def test_inject_program_appends_uservar(proto, c2s_environ):
    """inject_initial_program=QCMD → splice USERVAR IBMPROGRAM VALUE QCMD
    just before IAC SE. Tests the INLPGM override attack."""
    proto.inject_initial_program = "QCMD"
    out = proto.negotiate_hook(c2s_environ, "c2s", NegotiateOpts())
    # The injected sequence: NE_USERVAR + "IBMPROGRAM" + NE_VALUE + "QCMD"
    assert bytes([NE_USERVAR]) + b"IBMPROGRAM" + bytes([0x01]) + b"QCMD" in out
    # Original USER var still present
    assert b"ALICE" in out
    # Still well-formed: ends with IAC SE
    assert out[-2:] == bytes([0xFF, 0xF0])
    # Grew by exactly 1 + 10 + 1 + 4 = 16 bytes
    assert len(out) == len(c2s_environ) + 16


def test_inject_menu_appends_uservar(proto, c2s_environ):
    """IBMIMENU override — same mechanic, different USERVAR."""
    proto.inject_initial_menu = "MAIN"
    out = proto.negotiate_hook(c2s_environ, "c2s", NegotiateOpts())
    assert bytes([NE_USERVAR]) + b"IBMIMENU" + bytes([0x01]) + b"MAIN" in out
    assert out[-2:] == bytes([0xFF, 0xF0])


def test_inject_library_appends_uservar(proto, c2s_environ):
    """IBMCURLIB override — third variant."""
    proto.inject_current_library = "QGPL"
    out = proto.negotiate_hook(c2s_environ, "c2s", NegotiateOpts())
    assert bytes([NE_USERVAR]) + b"IBMCURLIB" + bytes([0x01]) + b"QGPL" in out
    assert out[-2:] == bytes([0xFF, 0xF0])


def test_inject_only_on_c2s(proto, c2s_environ):
    """Injection is c2s only — server→client traffic untouched.
    The server's SEND request must not get our injection echoed back."""
    proto.inject_initial_program = "QCMD"
    out = proto.negotiate_hook(c2s_environ, "s2c", NegotiateOpts())
    assert out == c2s_environ
    assert b"IBMPROGRAM" not in out


def test_inject_no_iac_se_does_nothing(proto):
    """If the data doesn't contain IAC SE (not a subnegotiation),
    don't blindly append — leave it alone."""
    proto.inject_initial_program = "QCMD"
    data = bytes([0xFF, 0xFD, 0x27])  # IAC DO NEW-ENVIRON — no SB...SE
    out = proto.negotiate_hook(data, "c2s", NegotiateOpts())
    assert out == data
