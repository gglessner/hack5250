"""
Cross-EXFMT differential analyzer (C1, C2) + RPG state fuzzer (C3).

C1 — PUTOVR stale-field detection
  PUTOVR + OVRDTA only retransmit fields whose conditioning indicator
  is on. If RPG forgets SETON, the field is ABSENT from the next WTD.
  The workstation keeps the stale value; next READ returns it as if
  the user typed it. IBM warns this is fragile (SC41-5715).

  Wire signature: same row-2 program header (MCOR/MCAD/etc), field at
  (r,c) present in screen N, absent in screen N+1.

C2 — Indicator-conditioned protect-flip detection
  A field that flips protected→input→protected across EXFMTs is driven
  by an indicator (DSPATR(PR) conditioned on *INxx). The flip IS the
  signature. Map which user input preceded the flip → that's the auth
  decision the program made.

C3 — RPG state echo-back fuzzer
  Direct port of hack3270_libs/attacks/state_fuzz.py. RPG programs
  stash state in hidden fields between EXFMTs (original keys, RRNs,
  auth flags). Find hidden fields whose content appeared in earlier
  user input → that's the echo-back. The LCS detector works unchanged.
  Adapted: _split_inbound for 5250 (cursor-before-AID), extra_sba uses
  row/col bytes, classify watches MCH/CPF/RNQ instead of DFHAC/ASRA.
"""
from dataclasses import dataclass, field as dc_field
from hackterm_core import Screen, Field


# ===========================================================================
# C1 — FieldFingerprint + ExfmtDiffer
# ===========================================================================

@dataclass
class FieldFingerprint:
    """Identity of a field across EXFMT cycles.

    Hashed/compared on (row, col, length) ONLY — protected/hidden are
    payload, not identity. This lets set-intersection find 'same field,
    attrs flipped' (C2's signature).
    """
    row: int
    col: int
    length: int
    protected: bool
    hidden: bool

    @classmethod
    def from_field(cls, f: Field) -> "FieldFingerprint":
        return cls(f.row, f.col, f.length, f.protected, f.hidden)

    def __hash__(self):
        return hash((self.row, self.col, self.length))

    def __eq__(self, other):
        if not isinstance(other, FieldFingerprint):
            return NotImplemented
        return (self.row, self.col, self.length) == (other.row, other.col, other.length)


@dataclass
class StaleField:
    """A field present in cycle N but absent in N+1. PUTOVR candidate."""
    fingerprint: FieldFingerprint
    last_seen_cycle: int
    last_content: bytes


class ExfmtDiffer:
    """Diff consecutive screens. Find PUTOVR stale fields + protect-flips.

    Attaches as a daemon observer. Builds per-format-header history
    (row-2 program ID — MCOR, MCAD, etc). Diffs each new screen against
    the previous one in the same format.

    History capped at 20 screens — enough for any reasonable EXFMT
    cycle, small enough to not eat memory on long sessions.
    """

    HISTORY_CAP = 20

    def __init__(self, protocol):
        self.protocol = protocol
        self.history: list[Screen] = []
        self.stale_findings: list[StaleField] = []
        self.flip_findings: list[dict] = []  # C2

    def attach(self, daemon):
        daemon.add_observer(self._observe)

    def _observe(self, data: bytes, direction: str):
        if direction != "s2c":
            return
        screen = self.protocol.parse(data)
        self._observe_screen(screen)

    def _observe_screen(self, screen: Screen):
        """Internal: take an already-parsed Screen. Split out so tests
        can drive with synthetic Screen objects without going through
        parse()."""
        if not self._same_format(screen):
            self.history = [screen]
            return
        if self.history:
            self._diff(self.history[-1], screen)
        self.history.append(screen)
        if len(self.history) > self.HISTORY_CAP:
            self.history.pop(0)

    def _same_format(self, screen: Screen) -> bool:
        """Heuristic: same program if row-2 header matches.

        Mels Cargo: 'MCAD', 'MCOR', 'MCMM' at r2c1-ish. We compare the
        first 10 chars of row 2 (rendered[1][:10]). If a screen has no
        row 2 (truncated/empty), treat as no-match → reset.
        """
        if not self.history:
            return True
        if len(screen.rendered) < 2 or len(self.history[-1].rendered) < 2:
            return False
        prev_header = self.history[-1].rendered[1][:10]
        curr_header = screen.rendered[1][:10]
        return prev_header == curr_header

    def _diff(self, prev: Screen, curr: Screen):
        """Compare prev → curr. Append to stale_findings / flip_findings."""
        prev_fps = {FieldFingerprint.from_field(f): f for f in prev.fields}
        curr_fps = {FieldFingerprint.from_field(f): f for f in curr.fields}

        # --- C1: Stale (in prev, not in curr) ---
        # PUTOVR didn't retransmit this field. Workstation kept old value.
        for fp in set(prev_fps) - set(curr_fps):
            f_prev = prev_fps[fp]
            self.stale_findings.append(StaleField(
                fingerprint=fp,
                last_seen_cycle=len(self.history),
                last_content=f_prev.content,
            ))

        # --- C2: Protect-flip (same position, protected attr changed) ---
        # Indicator-driven DSPATR(PR). The flip is the auth-decision tell.
        for fp in set(prev_fps) & set(curr_fps):
            f_prev = prev_fps[fp]
            f_curr = curr_fps[fp]
            if f_prev.protected != f_curr.protected:
                self.flip_findings.append({
                    "position": (fp.row, fp.col),
                    "length": fp.length,
                    "before": "protected" if f_prev.protected else "input",
                    "after": "protected" if f_curr.protected else "input",
                    "cycle": len(self.history),
                })

    def protect_flips_for_position(self, row: int, col: int) -> list[dict]:
        """All recorded flips at (row, col), in cycle order.

        Operator workflow: see a field unprotect, query this to find
        WHEN it flipped → correlate against what was sent at cycle-1."""
        return [f for f in self.flip_findings if f["position"] == (row, col)]


# ===========================================================================
# C3 — RPG state echo-back fuzzer
#
# PORT of hack3270_libs/attacks/state_fuzz.py. ~70% direct copy.
# Source line ranges cited per block. See the original for full
# rationale comments — only the 5250-specific deltas are re-explained
# here.
# ===========================================================================

import re
import time
import sqlite3
from typing import Optional, Literal

from hack5250.constants import HDR_LEN, ORD_SBA, IAC_EOR


# --- Data model (state_fuzz.py L41-64) — COPY VERBATIM -------------------

@dataclass
class Step:
    """One round-trip: host shows a screen, user responds."""
    host_screen: Screen
    user_input: bytes = b""
    timestamp: float = 0.0


@dataclass
class Flow:
    """A recorded sequence of Steps. Persisted to SQLite."""
    id: int
    name: str
    steps: list[Step] = dc_field(default_factory=list)


@dataclass
class EchoTarget:
    """A field in step N that echoes input from step M < N."""
    step_idx: int
    field_idx: int
    source_step: int
    confidence: float


# --- RPGStateFuzzer (state_fuzz.py L70-215) ------------------------------
# Renamed from StateFuzzer to avoid namespace collision if both packages
# are imported. Otherwise IDENTICAL: __init__, _init_schema, attach,
# start/stop_recording, load_flow, _observe, analyze.

class RPGStateFuzzer:
    """Record → analyze → mutate-replay. RPG state echo-back fuzzer.

    Architecture identical to hack3270's StateFuzzer. RPG programs
    stash state in hidden fields between EXFMTs (same idea as CICS
    COMMAREA round-tripping). The LCS detector finds it.
    """

    MIN_MATCH_LEN = 4  # state_fuzz.py L174

    def __init__(self, protocol, db: sqlite3.Connection):
        self.protocol = protocol
        self.db = db
        self.recording = False
        self.current_flow: Optional[Flow] = None
        self._init_schema()

    def _init_schema(self) -> None:
        # state_fuzz.py L80-101 — COPY VERBATIM
        cur = self.db.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS Flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                created REAL NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS Steps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id INTEGER NOT NULL,
                step_idx INTEGER NOT NULL,
                host_raw BLOB NOT NULL,
                user_input BLOB NOT NULL,
                timestamp REAL NOT NULL,
                FOREIGN KEY (flow_id) REFERENCES Flows(id)
            )
        """)
        self.db.commit()

    def attach(self, daemon) -> None:
        daemon.add_observer(self._observe)

    def start_recording(self, name: str) -> None:
        # state_fuzz.py L108-110
        self.current_flow = Flow(id=0, name=name, steps=[])
        self.recording = True

    def stop_recording(self) -> int:
        # state_fuzz.py L112-132 — COPY VERBATIM
        if not self.recording or self.current_flow is None:
            raise RuntimeError("not recording")
        self.recording = False
        cur = self.db.cursor()
        cur.execute("INSERT INTO Flows (name, created) VALUES (?, ?)",
                    (self.current_flow.name, time.time()))
        flow_id = cur.lastrowid
        for idx, step in enumerate(self.current_flow.steps):
            cur.execute(
                "INSERT INTO Steps (flow_id, step_idx, host_raw, user_input, timestamp) "
                "VALUES (?, ?, ?, ?, ?)",
                (flow_id, idx, step.host_screen.raw, step.user_input, step.timestamp)
            )
        self.db.commit()
        self.current_flow.id = flow_id
        return flow_id

    def load_flow(self, flow_id: int) -> Flow:
        # state_fuzz.py L134-153 — COPY VERBATIM
        cur = self.db.cursor()
        cur.execute("SELECT name FROM Flows WHERE id = ?", (flow_id,))
        row = cur.fetchone()
        if not row:
            raise KeyError(f"flow {flow_id} not found")
        flow = Flow(id=flow_id, name=row[0], steps=[])
        cur.execute(
            "SELECT host_raw, user_input, timestamp FROM Steps "
            "WHERE flow_id = ? ORDER BY step_idx", (flow_id,)
        )
        for host_raw, user_input, ts in cur.fetchall():
            screen = self.protocol.parse(bytes(host_raw))
            flow.steps.append(Step(host_screen=screen,
                                   user_input=bytes(user_input), timestamp=ts))
        return flow

    def _observe(self, data: bytes, direction: str) -> None:
        # state_fuzz.py L155-170 — COPY VERBATIM
        if not self.recording or self.current_flow is None:
            return
        if direction == "s2c":
            screen = self.protocol.parse(data)
            self.current_flow.steps.append(
                Step(host_screen=screen, user_input=b"", timestamp=time.time())
            )
        elif direction == "c2s":
            if self.current_flow.steps:
                self.current_flow.steps[-1].user_input = data

    def analyze(self, flow_id: int) -> list[EchoTarget]:
        # state_fuzz.py L176-215 — COPY VERBATIM
        # The LCS detector doesn't care about packet shape. It compares
        # field.content (EBCDIC) against user_input (raw bytes); the
        # EBCDIC field data lives somewhere in the inbound packet and
        # the LCS finds it without parsing inbound precisely.
        flow = self.load_flow(flow_id)
        targets: list[EchoTarget] = []
        for n in range(1, len(flow.steps)):
            screen = flow.steps[n].host_screen
            for f_idx, fld in enumerate(screen.fields):
                # TODO: tn5250.parse() doesn't populate Field.content
                # (see _parse_sf comment "filled by caller if needed").
                # analyze() against live packets blocked until that's
                # fixed — for now this only works with synthetic Steps.
                content = fld.content
                if len(content) < self.MIN_MATCH_LEN:
                    continue
                for m in range(n):
                    user_input = flow.steps[m].user_input
                    if not user_input:
                        continue
                    match_len = _longest_common_substring(content, user_input)
                    if match_len >= self.MIN_MATCH_LEN:
                        targets.append(EchoTarget(
                            step_idx=n, field_idx=f_idx,
                            source_step=m,
                            confidence=match_len / len(content),
                        ))
        targets.sort(key=lambda t: t.confidence, reverse=True)
        return targets


# --- LCS helper (state_fuzz.py L341-359) — COPY VERBATIM -----------------

def _longest_common_substring(a: bytes, b: bytes) -> int:
    if not a or not b:
        return 0
    best = 0
    for i in range(len(a)):
        for length in range(best + 1, len(a) - i + 1):
            if a[i:i + length] in b:
                best = length
            else:
                break
    return best


# --- _split_inbound — 5250 ADAPTATION ------------------------------------
# state_fuzz.py L385-413. REWRITTEN for 5250 packet shape.
#
# 3270 inbound:  AID(1) + cursor_addr(2) + [SBA(1)+addr(2)+data]* + IAC EOR
# 5250 inbound:  HDR(10) + cursor_row(1) + cursor_col(1) + AID(1)
#                + [SBA(1)+row(1)+col(1)+data]* + IAC EOR
#
# Key differences:
#   - 10-byte header prepended (3270 has none at this layer)
#   - Cursor BEFORE aid (3270 has aid first) — see tn5250.py:540 comment
#   - SBA address is row+col (1+1), not 3270's 12-bit encoded (2 bytes)
#
# We keep the header attached so reassembly is trivial (h + d + t == pkt).
# Mutations don't touch h or t.

def _split_inbound(pkt: bytes) -> tuple[bytes, bytes, bytes]:
    """Split a 5250 inbound packet into (header, data, trailer).

    header  = HDR(10) + cursor(2) + AID(1) [+ SBA(1)+row(1)+col(1) if present]
    data    = EBCDIC field bytes after the LAST SBA
    trailer = IAC EOR (or empty)
    """
    if pkt.endswith(IAC_EOR):
        body, trailer = pkt[:-2], IAC_EOR
    else:
        body, trailer = pkt, b""

    # Walk from HDR_LEN+3 (past cursor+AID) looking for the LAST SBA.
    # rfind would false-positive on data bytes equal to ORD_SBA (0x11),
    # so walk forward through SBA blocks. Each SBA is followed by
    # row(1)+col(1) where row<=27 (model 5, 27×132) — sanity check.
    last_sba = -1
    pos = HDR_LEN + 3
    while pos < len(body):
        if (body[pos] == ORD_SBA and pos + 2 < len(body)
                and 1 <= body[pos + 1] <= 27):
            last_sba = pos
            pos += 3
            # Skip data bytes until next SBA-shaped sequence or end.
            # We don't know the field length, so peek for the next
            # plausible SBA. Crude but adequate for fuzzing — same
            # heuristic as 3270's version.
            while pos < len(body):
                if (body[pos] == ORD_SBA and pos + 2 < len(body)
                        and 1 <= body[pos + 1] <= 27):
                    break
                pos += 1
        else:
            pos += 1

    if last_sba >= 0:
        return body[:last_sba + 3], body[last_sba + 3:], trailer

    # No SBA — AID-only (CLEAR, PA keys). Header is HDR + cursor + AID.
    cut = min(HDR_LEN + 3, len(body))
    return body[:cut], body[cut:], trailer


# --- Mutations (state_fuzz.py L378-462) ----------------------------------
# length_plus_1, length_double, type_confusion, step_swap: COPY VERBATIM
# extra_sba: ADAPTED for 5250 row/col addressing

Mutation = Literal["length_plus_1", "length_double", "type_confusion",
                   "extra_sba", "step_swap"]

_EBCDIC_DIGIT_LO, _EBCDIC_DIGIT_HI = 0xF0, 0xF9


def mutate_input(original: bytes, mutation: Mutation,
                 swap_with: Optional[bytes] = None) -> bytes:
    """Apply a mutation to a captured 5250 inbound packet.

    Mutations (same set as hack3270 — RPG concerns map to CICS concerns):
      length_plus_1  — append 1 byte; tests EXFMT length check
      length_double  — duplicate data; tests buffer overflow into next field
      type_confusion — numeric → alpha; tests RPG zoned-decimal validation
      extra_sba      — phantom field at r24c60; tests format-table validation
      step_swap      — replay other step's input; tests state desync
    """
    if mutation == "step_swap":
        if swap_with is None:
            raise ValueError("step_swap requires swap_with=")
        return swap_with

    header, data, trailer = _split_inbound(original)

    if mutation == "length_plus_1":
        # state_fuzz.py L434-438 — COPY VERBATIM
        return header + data + b"\xc1" + trailer

    elif mutation == "length_double":
        # state_fuzz.py L440-441 — COPY VERBATIM
        return header + data + data + trailer

    elif mutation == "type_confusion":
        # state_fuzz.py L443-452 — COPY VERBATIM
        if data and all(_EBCDIC_DIGIT_LO <= b <= _EBCDIC_DIGIT_HI for b in data):
            alpha = bytes((b - 0xF0) + 0xC0 if b != 0xF0 else 0xC1 for b in data)
            return header + alpha + trailer
        return original

    elif mutation == "extra_sba":
        # ADAPTED: 5250 SBA is [0x11][row][col] — 1-byte coords, not
        # 3270's 12-bit encode_addr(). Phantom at row 24 col 60
        # (bottom-right-ish, unlikely to overlap real fields).
        # state_fuzz.py L454-460 used encode_addr(1900); we use raw bytes.
        phantom = bytes([ORD_SBA, 24, 60]) + b"\xc8\xc1\xc3\xd2"  # "HACK" EBCDIC
        return header + data + phantom + trailer

    raise ValueError(f"unknown mutation: {mutation!r}")


# --- Result classification (state_fuzz.py L469-506) ----------------------
# ADAPTED: IBM i message IDs instead of CICS abend codes.

ResultClass = Literal["ABEND", "DISCONNECT", "SCREEN_DIFFERS", "IDENTICAL"]

# IBM i abend tells. The 5250 equivalents of 3270's DFHAC/ASRA/etc:
#   MCH1202 — decimal data error (packed/zoned got non-numeric) — THE classic
#   MCH3601 — pointer not set
#   CPFnnnn — OS message (CPF5068=subfile not active, CPF9999=function check)
#   RNQnnnn — RPG inquiry (program asks what to do — unexpected condition)
#   RNXnnnn — RPG exception (uncaught error in ILE program)
_ABEND_RE = re.compile(r'\b(MCH\d{4}|CPF\d{4}|RNQ\d{4}|RNX\d{4})\b')


def classify_result(actual_raw: Optional[bytes], expected_screen: Screen,
                    protocol) -> ResultClass:
    # state_fuzz.py L479-506 — COPY VERBATIM (only _ABEND_RE differs)
    if not actual_raw:
        return "DISCONNECT"
    actual_screen = protocol.parse(actual_raw)
    if _ABEND_RE.search(actual_screen.text):
        return "ABEND"
    if actual_screen.text == expected_screen.text:
        return "IDENTICAL"
    return "SCREEN_DIFFERS"


# --- screens_match_fuzzy (state_fuzz.py L509-532) — COPY VERBATIM --------

def screens_match_fuzzy(a: Screen, b: Screen) -> bool:
    """Same field count, same flags, same positions. Content ignored —
    timestamps in field content cause false negatives otherwise."""
    if len(a.fields) != len(b.fields):
        return False
    for fa, fb in zip(a.fields, b.fields):
        if (fa.row, fa.col) != (fb.row, fb.col):
            return False
        if fa.protected != fb.protected:
            return False
        if fa.hidden != fb.hidden:
            return False
        if fa.numeric != fb.numeric:
            return False
    return True
