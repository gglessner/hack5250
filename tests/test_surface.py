"""Surface analyzers — pure functions on Screen."""
import pytest
from hack5250.attacks.surface import get_hidden_content, tamper_map
from hackterm_core import Screen, Field, EbcdicCodec


@pytest.fixture
def codec():
    return EbcdicCodec()


def _screen(fields: list[Field]) -> Screen:
    s = Screen.empty()
    s.fields = fields
    return s


def test_hidden_content_extracts_nondisp_fields(codec):
    fields = [
        Field(row=1, col=1, length=10, protected=True, hidden=False,
              numeric=False, mdt=False, content=b"\xC8\xC5\xD3\xD3\xD6"),  # HELLO
        Field(row=2, col=1, length=10, protected=True, hidden=True,
              numeric=False, mdt=False, content=b"\xE2\xC5\xC3\xD9\xC5\xE3"),  # SECRET
    ]
    out = get_hidden_content(_screen(fields), codec)
    assert len(out) == 1
    assert out[0]["text"] == "SECRET"
    assert out[0]["row"] == 2
    assert out[0]["ebcdic_hex"] == "e2c5c3d9c5e3"


def test_hidden_content_empty_when_none_hidden(codec):
    fields = [Field(1, 1, 5, True, False, False, False, b"\xC1\xC2\xC3")]
    assert get_hidden_content(_screen(fields), codec) == []


def test_hidden_content_includes_field_index(codec):
    fields = [
        Field(1, 1, 5, True, False, False, False, b""),
        Field(2, 1, 5, True, True, False, False, b"\xC1"),
        Field(3, 1, 5, True, False, False, False, b""),
    ]
    out = get_hidden_content(_screen(fields), codec)
    assert out[0]["field_idx"] == 1


def test_tamper_map_ranks_digit_fields_high(codec):
    fields = [
        Field(1, 1, 10, True, False, False, False, codec.to_ebcdic("129.59")),
        Field(2, 1, 80, True, False, False, False, codec.to_ebcdic(" " * 80)),
    ]
    out = tamper_map(_screen(fields), codec)
    assert out[0]["row"] == 1
    assert "contains digits" in out[0]["reasons"]


def test_tamper_map_ranks_hidden_highest(codec):
    fields = [
        Field(1, 1, 10, True, False, False, False, codec.to_ebcdic("12345")),
        Field(2, 1, 10, True, True, False, False, codec.to_ebcdic("ADMIN")),
    ]
    out = tamper_map(_screen(fields), codec)
    assert out[0]["row"] == 2
    assert "HIDDEN" in out[0]["reasons"]


def test_tamper_map_ranks_short_fields_high(codec):
    fields = [
        Field(1, 1, 4, True, False, False, False, codec.to_ebcdic("1337")),
        Field(2, 1, 60, True, False, False, False, codec.to_ebcdic("Mels Cargo Main Menu" + " " * 40)),
    ]
    out = tamper_map(_screen(fields), codec)
    assert out[0]["row"] == 1
    assert "short (flag/code length)" in out[0]["reasons"]


def test_tamper_map_penalizes_blanks(codec):
    fields = [Field(1, 1, 10, True, False, False, False, b"\x40" * 10)]
    out = tamper_map(_screen(fields), codec)
    assert "blank" in out[0]["reasons"]
    assert out[0]["score"] < 0


def test_tamper_map_penalizes_long_decorative(codec):
    fields = [Field(1, 1, 200, True, False, False, False, codec.to_ebcdic(":" * 200))]
    out = tamper_map(_screen(fields), codec)
    assert "long (decorative)" in out[0]["reasons"]


def test_tamper_map_skips_input_fields(codec):
    fields = [Field(1, 1, 5, False, False, False, False, b"")]
    assert tamper_map(_screen(fields), codec) == []


def test_tamper_map_notes_input_length_match(codec):
    fields = [
        Field(1, 1, 7, False, False, False, False, b""),  # input
        Field(2, 1, 7, True, False, False, False, codec.to_ebcdic("ECHO123")),
    ]
    out = tamper_map(_screen(fields), codec)
    assert any("length matches an input field" in r for r in out[0]["reasons"])
