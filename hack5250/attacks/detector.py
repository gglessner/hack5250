"""
IBM i message-ID detection — the abend/oracle harvester.

Direct port of hack3270's ESMFingerprinter (attacks/esm_passive.py)
for the IBM i CPF/MCH/RNQ message-ID space. Observer-attached.

The CPF1107/CPF1120 pair is the username-enumeration oracle:
  CPF1107 "Password not correct" → userid IS valid
  CPF1120 "User does not exist"  → userid is NOT valid
Same disclosure as 3270's DFHCE3530/3532, but always present —
IBM i can't be configured to suppress these like CICS TS 5.1+ can.

MCH1202 is the abend you WANT during fuzzing — your numeric injection
landed in a packed/zoned field. The Display Program Messages panel
that follows leaks program/library/statement number.
"""
import re


_RULES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r'\bMCH1202\b'),  'decimal_data_error',
     'Decimal data error — packed/zoned field got non-numeric bytes'),
    (re.compile(r'\bMCH3601\b'),  'null_pointer',
     'Pointer not set — RPG used unset basing pointer'),
    (re.compile(r'\bCPF1107\b'),  'username_oracle',
     'Password not correct — USERID IS VALID (oracle)'),
    (re.compile(r'\bCPF1120\b'),  'username_oracle',
     'User does not exist (the other half of the oracle)'),
    (re.compile(r'\bCPF1394\b'),  'account_state_leak',
     'User profile cannot sign on — disabled or restricted'),
    (re.compile(r'\bCPF2204\b'),  'object_not_found',
     'User profile not found at object level (auth-layer distinction)'),
    (re.compile(r'\bCPD0078\b'),  'dds_validation_fired',
     'DDS VALUES/RANGE/COMP rejected — host re-validates (good for them)'),
    (re.compile(r'\bRNQ\d{4}\b'), 'rpg_inquiry',
     'RPG inquiry message — program hit unexpected condition'),
    (re.compile(r'\bRNX\d{4}\b'), 'rpg_exception',
     'RPG exception — uncaught error in ILE program'),
    (re.compile(r'Display Program Messages'), 'stack_trace_leak',
     'DSPPGMMSG panel — leaks program/library/statement number'),
]

# IBM i panels render labels with space-separated dots: "Program . . . . :   NAME"
# [\.\s]+ accepts that; \.+ would not.
_PROG_RE = re.compile(r'Program\s*[\.\s]+:\s*(\w+)')
_LIB_RE  = re.compile(r'Library\s*[\.\s]+:\s*(\w+)')


class IBMiMessageDetector:
    """Passive observer. Watches every s2c screen for IBM i message IDs.

    findings: dict[str, list[str]] — finding key → matched texts.
    Same shape as hack3270's ESMFingerprinter.findings.
    """

    def __init__(self, protocol):
        self.protocol = protocol
        self.findings: dict[str, list[str]] = {}

    def attach(self, daemon):
        daemon.add_observer(self._observe)

    def _observe(self, data: bytes, direction: str):
        if direction != "s2c":
            return
        screen = self.protocol.parse(data)
        text = screen.text
        for pattern, key, _desc in _RULES:
            for match in pattern.finditer(text):
                self.findings.setdefault(key, []).append(match.group(0))
        if 'stack_trace_leak' in self.findings:
            self._extract_stack_frame(text)

    def _extract_stack_frame(self, text: str):
        # Screen.text joins rows with '\n'. The 80-col wrap is a render
        # artifact — the datastream bytes are contiguous, so a value can
        # split mid-word at col 80. Strip the newlines (don't replace with
        # space — that would leave a gap where the wrap fell).
        flat = text.replace('\n', '')
        prog = _PROG_RE.search(flat)
        lib = _LIB_RE.search(flat)
        if prog:
            qualified = f"{lib.group(1) if lib else '?'}/{prog.group(1)}"
            leaked = self.findings.setdefault('leaked_programs', [])
            if qualified not in leaked:
                leaked.append(qualified)

    @property
    def summary(self) -> dict[str, int]:
        return {k: len(v) for k, v in self.findings.items()}


# === STRPCCMD canary (CVE-2005-0868) — defensive ===

_PCO_PATTERN = re.compile(rb'\x04\xf3..\xd9')


class STRPCCMDCanary:
    """Defensive: detect host→client RCE attempt via STRPCCMD.

    CVE-2005-0868 — STRPCO+STRPCCMD sends a 5250 structured-field escape
    that makes IBM iAccess/PCOMM execute arbitrary commands on the
    operator's PC. The ONLY host→client RCE in the protocol.
    """

    def __init__(self):
        self.alerts: list[dict] = []

    def attach(self, daemon):
        daemon.add_observer(self._observe)

    def _observe(self, data: bytes, direction: str):
        if direction != "s2c":
            return
        match = _PCO_PATTERN.search(data)
        if match:
            start = max(0, match.start() - 4)
            end = min(len(data), match.end() + 32)
            self.alerts.append({
                "raw_hex": data[start:end].hex(),
                "match_offset": match.start(),
                "warning": (
                    "STRPCCMD escape sequence detected — host attempting "
                    "client-side command execution (CVE-2005-0868). "
                    "If your emulator is IBM iAccess/PCOMM, it may have "
                    "executed the embedded command."
                ),
            })
