"""
Surface analyzers — pure functions on Screen. No wire traffic.

Live finding (Mels Cargo, 2026-04-08): hidden "99) Delete Order
History" was always in screen.text — parse() reads field content
regardless of attr. These functions surface it cleanly.
"""
from hackterm_core import Screen, EbcdicCodec


def get_hidden_content(screen: Screen, codec: EbcdicCodec) -> list[dict]:
    """Just the NONDISP fields, decoded."""
    out = []
    for i, f in enumerate(screen.fields):
        if not f.hidden:
            continue
        out.append({
            "field_idx": i,
            "row": f.row, "col": f.col, "length": f.length,
            "ebcdic_hex": f.content.hex(),
            "text": codec.to_ascii(f.content),
        })
    return out


def tamper_map(screen: Screen, codec: EbcdicCodec) -> list[dict]:
    """Protected fields ranked by interestingness.
      +4 hidden, +3 digits, +3 short(1-4), +2 input-len-match,
      -2 blank, -2 long(>50)
    """
    input_lengths = {f.length for f in screen.fields if not f.protected}

    ranked = []
    for i, f in enumerate(screen.fields):
        if not f.protected:
            continue
        text = codec.to_ascii(f.content)
        score = 0
        reasons: list[str] = []

        if f.hidden:
            score += 4; reasons.append("HIDDEN")
        if any(c.isdigit() for c in text):
            score += 3; reasons.append("contains digits")
        if 1 <= f.length <= 4:
            score += 3; reasons.append("short (flag/code length)")
        if f.length in input_lengths:
            score += 2; reasons.append(f"length matches an input field ({f.length})")
        if not text.strip():
            score -= 2; reasons.append("blank")
        if f.length > 50:
            score -= 2; reasons.append("long (decorative)")

        ranked.append({
            "field_idx": i, "row": f.row, "col": f.col, "length": f.length,
            "score": score, "reasons": reasons,
            "current_value": text[:40],
        })

    ranked.sort(key=lambda x: -x["score"])
    return ranked
