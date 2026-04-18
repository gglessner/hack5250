import pytest
from hack5250.tn5250 import TN5250
from hackterm_core import Screen


@pytest.fixture
def proto():
    return TN5250()


def test_parse_minimal_returns_screen(proto, pkt_minimal):
    s = proto.parse(pkt_minimal)
    assert isinstance(s, Screen)
    assert s.rows == 24
    assert s.cols == 80


def test_parse_empty_input_returns_empty_screen(proto):
    s = proto.parse(b"")
    assert s.fields == []


def test_parse_too_short_for_header(proto):
    """Less than 10 bytes — can't even read the header. Don't crash."""
    s = proto.parse(b"\x00\x05\x12")
    assert s.fields == []


def test_parse_one_input_field(proto, pkt_one_input_field):
    s = proto.parse(pkt_one_input_field)
    assert len(s.fields) == 1
    f = s.fields[0]
    assert f.row == 5
    assert f.col == 10
    assert f.length == 8
    assert f.protected is False
    assert f.hidden is False
    assert f.numeric is False


def test_parse_protected_field(proto, pkt_protected_field):
    """FFW bypass bit set → Field.protected = True."""
    s = proto.parse(pkt_protected_field)
    assert len(s.fields) == 1
    assert s.fields[0].protected is True


def test_parse_hidden_field(proto, pkt_hidden_field):
    """ATTR_NONDISP → Field.hidden = True."""
    s = proto.parse(pkt_hidden_field)
    assert len(s.fields) == 1
    assert s.fields[0].hidden is True


def test_parse_numeric_field(proto, pkt_numeric_field):
    """FFW shift bits = numeric-only → Field.numeric = True."""
    s = proto.parse(pkt_numeric_field)
    assert len(s.fields) == 1
    assert s.fields[0].numeric is True


def test_parse_signon_screen_three_fields(proto, pkt_signon_screen):
    """The realistic fixture: 3 fields (label, user, password)."""
    s = proto.parse(pkt_signon_screen)
    assert len(s.fields) == 3
    # Label: output-only, no FFW means not an input field but still a Field
    label, user, password = s.fields
    assert label.row == 1 and label.col == 36
    assert user.row == 6 and user.col == 17 and user.length == 10
    assert user.hidden is False
    assert password.row == 7 and password.col == 17
    assert password.hidden is True


def test_parse_renders_text(proto, pkt_signon_screen):
    """Text bytes after a field def should appear in the rendered grid."""
    s = proto.parse(pkt_signon_screen)
    # "Sign On" should appear somewhere in the text
    assert "Sign On" in s.text


def test_parse_soh_extracts_pf_mask(proto, pkt_with_soh):
    """The PF-key mask in SOH tells us which keys the host considers valid.
    Stored on Screen for the SOH-mask-bypass attack."""
    s = proto.parse(pkt_with_soh)
    # Custom attribute on Screen (we'll add it via dataclass field or just setattr)
    # F3=bit2, F12=bit11 → 0x201000
    assert hasattr(s, 'pf_mask')
    assert s.pf_mask == 0x201000


def test_parse_clear_unit_resets_fields(proto):
    """ESC + Clear Unit should empty the field list.
    Build inline: clear, then a field, then clear again."""
    from hack5250.constants import ESC, CMD_CLEAR_UNIT, CMD_WRITE_TO_DISPLAY, ORD_SBA, ORD_SF, ATTR_GREEN
    from tests.conftest import make_header, make_ffw

    body = bytes([ESC, CMD_WRITE_TO_DISPLAY, 0x00, 0x00])
    body += bytes([ORD_SBA, 1, 1, ORD_SF]) + make_ffw() + bytes([ATTR_GREEN, 0x00, 0x05])
    body += bytes([ESC, CMD_CLEAR_UNIT])  # clear AFTER defining a field
    pkt = make_header(len(body) + 2) + body + bytes([0xFF, 0xEF])

    s = proto.parse(pkt)
    assert s.fields == []  # cleared


def test_parse_preserves_raw(proto, pkt_one_input_field):
    """Screen.raw must hold the original bytes for replay."""
    s = proto.parse(pkt_one_input_field)
    assert s.raw == pkt_one_input_field


def test_parse_output_only_field_no_ffw(proto):
    """SF immediately followed by a screen-attribute byte (0x20-0x3F)
    means no FFW — output-only field. The attr byte's top bits aren't 01."""
    from hack5250.constants import ESC, CMD_WRITE_TO_DISPLAY, ORD_SBA, ORD_SF, ATTR_WHITE
    from tests.conftest import make_header

    body = bytes([ESC, CMD_WRITE_TO_DISPLAY, 0x00, 0x00])
    body += bytes([ORD_SBA, 2, 2])
    body += bytes([ORD_SF, ATTR_WHITE, 0x00, 0x05])  # SF + attr (no FFW)
    pkt = make_header(len(body) + 2) + body + bytes([0xFF, 0xEF])

    s = proto.parse(pkt)
    assert len(s.fields) == 1
    f = s.fields[0]
    assert f.protected is True   # output-only is implicitly protected
    assert f.length == 5
