"""
ExfmtDiffer (C1) — cross-EXFMT differential analyzer.

PUTOVR detection: a field present in screen N but absent in screen N+1
(same program header) was conditionally NOT retransmitted. The
workstation keeps the stale value; next inbound returns it as if the
user typed it. IBM warns this is fragile (SC41-5715 PUTOVR section).

We diff consecutive Screens by FieldFingerprint (row,col,length —
hashable identity). Set difference finds stale fields. Set intersection
checked for protected-attribute flips (→ C2).
"""
import pytest
from hackterm_core import Screen


# === FieldFingerprint dataclass ===

def test_fingerprint_hashable():
    """FieldFingerprint must go in a set — hash on (row, col, length)."""
    from hack5250.attacks.differential import FieldFingerprint
    fp1 = FieldFingerprint(row=5, col=10, length=8, protected=True, hidden=False)
    fp2 = FieldFingerprint(row=5, col=10, length=8, protected=False, hidden=True)
    # Same position+length → same hash, even with different attrs.
    # (Attrs are payload, not identity — we use position to track a field
    #  ACROSS cycles where its attrs may flip.)
    assert hash(fp1) == hash(fp2)
    assert len({fp1, fp2}) == 1  # set deduplicates: position-equal → one element


def test_fingerprint_from_field():
    from hack5250.attacks.differential import FieldFingerprint
    f = pytest.mk_field(row=3, col=20, length=12, protected=True, hidden=True)
    fp = FieldFingerprint.from_field(f)
    assert fp.row == 3
    assert fp.col == 20
    assert fp.length == 12
    assert fp.protected is True
    assert fp.hidden is True


def test_fingerprint_equality_position_only():
    """Two fingerprints at the same position are equal regardless of attrs.
    This is what makes set intersection find 'same field, attrs flipped'."""
    from hack5250.attacks.differential import FieldFingerprint
    a = FieldFingerprint(5, 10, 8, protected=True, hidden=False)
    b = FieldFingerprint(5, 10, 8, protected=False, hidden=False)
    assert a == b


# === ExfmtDiffer construction & attach ===

def test_differ_starts_empty():
    from hack5250.attacks.differential import ExfmtDiffer
    from hack5250.tn5250 import TN5250
    d = ExfmtDiffer(TN5250())
    assert d.history == []
    assert d.stale_findings == []
    assert d.flip_findings == []


def test_differ_attaches_to_daemon(fake_daemon):
    """attach() registers _observe as a daemon observer."""
    from hack5250.attacks.differential import ExfmtDiffer
    from hack5250.tn5250 import TN5250
    d = ExfmtDiffer(TN5250())
    d.attach(fake_daemon)
    assert d._observe in fake_daemon._observers


# === _same_format heuristic ===

def test_same_format_matches_identical_header():
    from hack5250.attacks.differential import ExfmtDiffer
    from hack5250.tn5250 import TN5250
    d = ExfmtDiffer(TN5250())
    s1 = pytest.mk_screen([], header_text="MCOR    ")
    s2 = pytest.mk_screen([], header_text="MCOR    ")
    d.history = [s1]
    assert d._same_format(s2) is True


def test_same_format_rejects_different_header():
    """MCOR → MCAD is a different program. Reset history, don't diff."""
    from hack5250.attacks.differential import ExfmtDiffer
    from hack5250.tn5250 import TN5250
    d = ExfmtDiffer(TN5250())
    s1 = pytest.mk_screen([], header_text="MCOR    ")
    s2 = pytest.mk_screen([], header_text="MCAD    ")
    d.history = [s1]
    assert d._same_format(s2) is False


def test_same_format_first_screen_always_true():
    """No history → trivially same format (nothing to compare against)."""
    from hack5250.attacks.differential import ExfmtDiffer
    from hack5250.tn5250 import TN5250
    d = ExfmtDiffer(TN5250())
    s = pytest.mk_screen([])
    assert d._same_format(s) is True


# === _diff: stale field detection (C1 core) ===

def test_diff_finds_stale_field():
    """Field at (5,10) in prev, NOT in curr → stale finding."""
    from hack5250.attacks.differential import ExfmtDiffer
    from hack5250.tn5250 import TN5250
    d = ExfmtDiffer(TN5250())
    prev = pytest.mk_screen([
        pytest.mk_field(5, 10, 8, content=b"\xc1\xc2\xc3"),
        pytest.mk_field(7, 20, 4),
    ])
    curr = pytest.mk_screen([
        pytest.mk_field(7, 20, 4),  # only this one survived
    ])
    d.history = [prev]  # cycle 0
    d._diff(prev, curr)
    assert len(d.stale_findings) == 1
    sf = d.stale_findings[0]
    assert sf.fingerprint.row == 5
    assert sf.fingerprint.col == 10
    assert sf.last_content == b"\xc1\xc2\xc3"


def test_diff_no_stale_when_all_fields_present():
    """All prev fields still in curr → no stale findings."""
    from hack5250.attacks.differential import ExfmtDiffer
    from hack5250.tn5250 import TN5250
    d = ExfmtDiffer(TN5250())
    fields = [pytest.mk_field(5, 10, 8), pytest.mk_field(7, 20, 4)]
    prev = pytest.mk_screen(fields)
    curr = pytest.mk_screen(fields)
    d.history = [prev]
    d._diff(prev, curr)
    assert d.stale_findings == []


def test_diff_new_field_not_stale():
    """Field in curr but not in prev is just new — NOT stale."""
    from hack5250.attacks.differential import ExfmtDiffer
    from hack5250.tn5250 import TN5250
    d = ExfmtDiffer(TN5250())
    prev = pytest.mk_screen([pytest.mk_field(5, 10, 8)])
    curr = pytest.mk_screen([
        pytest.mk_field(5, 10, 8),
        pytest.mk_field(9, 30, 6),  # new
    ])
    d.history = [prev]
    d._diff(prev, curr)
    assert d.stale_findings == []


# === Observer integration (s2c → parse → diff → history) ===

def test_observe_ignores_c2s(fake_daemon):
    """Only s2c traffic produces screens."""
    from hack5250.attacks.differential import ExfmtDiffer
    from hack5250.tn5250 import TN5250
    d = ExfmtDiffer(TN5250())
    d.attach(fake_daemon)
    fake_daemon.fire_c2s(b"\x00" * 20)
    assert d.history == []


def test_observe_appends_history(fake_daemon, pkt_one_input_field):
    from hack5250.attacks.differential import ExfmtDiffer
    from hack5250.tn5250 import TN5250
    d = ExfmtDiffer(TN5250())
    d.attach(fake_daemon)
    fake_daemon.fire_s2c(pkt_one_input_field)
    assert len(d.history) == 1
    assert len(d.history[0].fields) == 1


def test_observe_history_capped(fake_daemon, pkt_one_input_field):
    """History caps at 20 — older screens evicted."""
    from hack5250.attacks.differential import ExfmtDiffer
    from hack5250.tn5250 import TN5250
    d = ExfmtDiffer(TN5250())
    d.attach(fake_daemon)
    for _ in range(25):
        fake_daemon.fire_s2c(pkt_one_input_field)
    assert len(d.history) == 20


def test_observe_different_format_resets_history(fake_daemon):
    """Different row-2 header → history resets to just the new screen."""
    from hack5250.attacks.differential import ExfmtDiffer
    from hack5250.tn5250 import TN5250
    d = ExfmtDiffer(TN5250())
    d.attach(fake_daemon)
    # Manually drive _observe with pre-built Screens (skip parse)
    s_mcor = pytest.mk_screen([pytest.mk_field(1, 1, 4)], header_text="MCOR")
    s_mcad = pytest.mk_screen([pytest.mk_field(1, 1, 4)], header_text="MCAD")
    d.history = [s_mcor, s_mcor, s_mcor]
    # _observe checks _same_format then either appends or resets
    d._observe_screen(s_mcad)
    assert len(d.history) == 1
    assert "MCAD" in "".join(d.history[0].rendered[1])


# ===========================================================================
# C2 — Protect-flip detection
# ===========================================================================

def test_diff_finds_protect_flip():
    """Field at (5,10) was protected in prev, input in curr → flip finding.

    This is the indicator-conditioned DSPATR(PR) signature. The program
    decided something (auth check passed?) and unprotected the field."""
    from hack5250.attacks.differential import ExfmtDiffer
    from hack5250.tn5250 import TN5250
    d = ExfmtDiffer(TN5250())
    prev = pytest.mk_screen([pytest.mk_field(5, 10, 8, protected=True)])
    curr = pytest.mk_screen([pytest.mk_field(5, 10, 8, protected=False)])
    d.history = [prev]
    d._diff(prev, curr)
    assert len(d.flip_findings) == 1
    flip = d.flip_findings[0]
    assert flip["position"] == (5, 10)
    assert flip["before"] == "protected"
    assert flip["after"] == "input"


def test_diff_no_flip_when_protected_unchanged():
    """Same field, same protected state → no flip."""
    from hack5250.attacks.differential import ExfmtDiffer
    from hack5250.tn5250 import TN5250
    d = ExfmtDiffer(TN5250())
    prev = pytest.mk_screen([pytest.mk_field(5, 10, 8, protected=True)])
    curr = pytest.mk_screen([pytest.mk_field(5, 10, 8, protected=True)])
    d.history = [prev]
    d._diff(prev, curr)
    assert d.flip_findings == []


def test_protect_flips_for_position():
    """Query helper: all flips at one position, in cycle order."""
    from hack5250.attacks.differential import ExfmtDiffer
    from hack5250.tn5250 import TN5250
    d = ExfmtDiffer(TN5250())
    d.flip_findings = [
        {"position": (5, 10), "before": "protected", "after": "input",
         "length": 8, "cycle": 1},
        {"position": (7, 20), "before": "input", "after": "protected",
         "length": 4, "cycle": 2},
        {"position": (5, 10), "before": "input", "after": "protected",
         "length": 8, "cycle": 3},
    ]
    flips = d.protect_flips_for_position(5, 10)
    assert len(flips) == 2
    assert flips[0]["cycle"] == 1
    assert flips[1]["cycle"] == 3
