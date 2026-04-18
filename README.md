# hack5250

**The first publicly-available tn5250 MITM proxy for IBM i (AS/400) penetration testing.**

A sibling to [hack3270](https://github.com/gglessner/hack3270). Same architecture — sit between the emulator and the host, manipulate the datastream in flight — but for the 5250 protocol instead of 3270. Built on the shared `hackterm-core` package.

```
[tn5250 emulator] ←→ [hack5250 proxy :5251] ←→ [IBM i :23]
                          ↑
                    [API :52500] ←→ [MCP server] ←→ [AI agent]
```

**Author:** Garland Glessner <gglessner@gmail.com>
**License:** GPL-3.0

---

## What it does

| Attack | Mechanism | Live-proven |
|---|---|---|
| **NONDISP reveal** | Rewrite screen-attribute byte `0x27` (non-display) → `0x20` (green) or `0x22` (white). Hidden fields become visible. | ✅ Found `99) Delete Order History` hidden via `DSPATR(ND)` on Mels Cargo |
| **FFW BYPASS clear** | Clear bit `0x2000` in the Field Format Word. Protected fields become editable. *Selective* — only fires on hidden fields to avoid breaking the format-table contract. | ✅ |
| **Protected-field tampering** | Build inbound packets with SBA pairs pointing at protected positions. If the host's `RECEIVE` doesn't validate SBA addresses against the format table, the write goes through. | ✅ Price `$129.59` → `$0.01129.59`, **persisted to order database** |
| **IBMRSEED downgrade** | Strip the RFC 2877 server seed from `NEW-ENVIRON` negotiation. Client falls back to cleartext password in `IBMSUBSPW`. Proxy captures it. | — (needs reconnect to test) |
| **DEVNAME spoof** | Rewrite the `DEVNAME` USERVAR. If `CRTDEVDSP USRPRF(...)` ties device descriptions to user profiles, spoofing yields auto-signon. | — |
| **ATTN escape** | Header flag bit `0x40` (not an AID). Drops to Operational Assistant → F9 → CL command line. The Silent Signal technique, automated. | Tested (blocked on emulated env) |
| **SOH PF-mask analysis** | Read the 24-bit mask from the SOH order. Find F-keys the host says are *invalid* — those are the interesting ones. Send them anyway. | ✅ All 24 keys masked on Mels Cargo, but F5 worked |

### Phase 3 attacks (`attacks/` modules)

| Attack | Module | Mechanism |
|---|---|---|
| **USERVAR injection** | `tn5250.py` | Splice `IBMPROGRAM`/`IBMIMENU`/`IBMCURLIB` into `NEW-ENVIRON IS` before `IAC SE`. The Telnet server processes these *before* QDSIGNON loads — operator types valid creds, lands at `QCMD` instead of their menu. Display-file field protection irrelevant. |
| **QDSignon buffer mapping** | `preauth.py` | IBM mandates the 178-byte buffer layout (USERID/PASSWRD/PROGRAM/MENU/CURLIB/UBUFFER). Sort input fields by position, zip with the layout. `position_of("PROGRAM")` finds where to SBA-write even when `DSPATR(ND)` hidden. |
| **RFC 4777 username oracle** | `preauth.py` | Set `IBMSENDCONFREC=YES`, send garbage password. Startup Response code at marker+10: `F0F0F0F2`=user-not-found, `F0F0F0F4`=user-exists-bad-password, `F0F0F0F8`=warns-before-lockout. The host *tells you* before it would lock the account. |
| **CA-AID + data — the impossible packet** | `ca_key.py` | DDS `CAnn` keys send AID byte only — no data, no validation. Real emulators enforce this terminal-side. The datastream doesn't. Send `[cursor][CA-AID][SBA][data]`. RPG branching on `*INKx` for a CA path skips re-validation; EXFMT already deposited tampered data. |
| **RTNCSRLOC cursor spoof** | `ca_key.py` | `RTNCSRLOC(&RCD &FLD)` translates inbound cursor coords → DDS field name → RPG variable. Put cursor on a *protected* field's coords (not a tab stop, but the inbound packet doesn't know that). Program branches on a field name the user couldn't have clicked. |
| **Subfile RRN tampering** | `ca_key.py` | RRN travels as a hidden 4-digit zoned field. `READC` returns it; programs `UPDATE SFLREC` using it. Detect: hidden field whose F0-F9 content incremented after ROLLUP. Tamper: option=4 at row 5 applies to record 9999 instead. RRN=0 crashes EXFMT (CPF5068). |
| **PUTOVR stale-field detector** | `differential.py` | `PUTOVR`+`OVRDTA` only retransmit fields whose conditioning indicator is on. RPG forgets `SETON` → field absent from next WTD → workstation keeps stale value → next read returns it as if user typed it. Diff consecutive screens by `(row,col,length)` fingerprint. |
| **Protect-flip detector** | `differential.py` | A field that flips protected→input across EXFMTs is driven by an indicator (`DSPATR(PR)` conditioned on `*INxx`). The flip *is* the auth-decision tell. Map which user input preceded the flip. |
| **RPG state echo-back fuzzer** | `differential.py` | Direct port of hack3270's `state_fuzz.py`. Record EXFMT round-trips → SQLite → LCS analyze (find hidden fields echoing earlier user input) → mutate-replay. 5250 adaptations: `_split_inbound` for HDR+cursor+AID layout, `extra_sba` uses row/col bytes, classify watches MCH/CPF/RNQ/RNX. |
| **FieldBruter** | `brute.py` | Send known-wrong baseline (`@@@@`), hash response. Iterate candidates (FFW-inferred numeric vs alphanumeric, or wordlist). Stop when hash differs. SQLite checkpoint every 50 → resumable. **Live-proven:** supervisor PIN `1337` at r18c23. |
| **ProgramEnumerator** | `brute.py` | Harvest program names from row-2 headers in storage logs (`MCMM`, `MCOR`, `MCAD`). Infer common prefix. Brute the suffix space (26²=676 at 0.5s ≈ 6 min). **Live-proven:** post-APCT abend, typing program name restarted transaction with no re-auth. |
| **FCW self-check strip** | `tn5250.py` | Strip Luhn/mod-11 self-check FCWs — terminal-side validation that the host trusts blindly. |
| **Write Error Code suppression** | `tn5250.py` | Blank the error text in WTD `WEC` orders. Hide brute-force noise from anyone watching the operator screen. |
| **IBMiMessageDetector** | `detector.py` | Passive harvester for CPF/MCH/RNQ message IDs in s2c traffic. Stack-frame extraction from DSPPGMMSG-format panels. |
| **STRPCCMD canary** | `detector.py` | CVE-2005-0868 — `STRPCCMD` lets the host run commands on the PC. Watch for WSF class `0xD9` structured fields. Defensive: alert if a 5250 app tries to run code on the operator's machine. |

---

## Install & run

```bash
# From the repo root — hackterm-core is vendored and loaded via sys.path,
# so only hack5250's own deps need installing.
pip3 install -e ".[dev,gui]"

# Start the proxy
python hack5250.py <ibmi_ip> 23 -n <project_name>

# Point your emulator (tn5250, x5250, IBM i ACS, tn5250j) at:
#   127.0.0.1:5251
```

| Flag | Default | What |
|---|---|---|
| `-n NAME` | `ibmi_pentest` | Project name — SQLite log becomes `<name>.db` |
| `-p PORT` | `5251` | Local proxy port (5250+1, mirrors hack3270's 3271) |
| `--api-port` | `52500` | API listener (hack3270 uses 31337 — both can run together) |
| `-t` | off | TLS to the IBM i (port 992 typically) |
| `-c CODEPAGE` | `cp037` | EBCDIC codepage (`cp037`, `cp500`, `cp1140`) |
| `-d` | off | Debug logging |

---

## GUI

Five tabs, same family style as hack3270.

### Hack FFW
Master ON/OFF button + checkboxes. Click ON → screen refreshes immediately with the mutations applied.

| Checkbox | What it does | Default |
|---|---|---|
| Disable Field Protection | Clear FFW BYPASS — **only on hidden fields** (5250's format table is a host contract; clearing BYPASS on visible decorative fields breaks navigation). The selective constraint was found against a live target. | ✅ |
| Enable Hidden Fields | Rewrite NONDISP attr → visible. The safe surgical option. | ✅ |
| Remove Numeric/Mandatory | Clear FFW shift bits + mandatory-entry + field-exit-required. Lets you type alpha into numeric fields. | ✅ |
| High Visibility | Revealed fields go white instead of green. | ✅ |

### Inject AID
Grid of F1-24 + ROLLUP/ROLLDN/HELP/PRINT/CLEAR + PA1-3. Direct-fire — click sends immediately.

Big red **ATTN** button on the right — the Silent Signal escape. Plus a "Send All Masked Keys" button that fires every F-key the SOH bitmap said was invalid.

### Negotiation
- **Strip IBMRSEED** checkbox — arm before the emulator connects. Captured creds appear in the dock when the downgrade succeeds.
- **DEVNAME spoof** — text entry + 76-name wordlist dropdown.

### Inject Into Fields
The `****` mask trick from hack3270, adapted. Type asterisks in the target field, hit Setup, then iterate a wordlist (CL commands, default Q* users, device names).

### Logs
SQLite-backed packet log. Hex + EBCDIC detail pane on click. Sortable, alternating rows.

### Captured Credentials dock (right side, always visible)
Goes bright red when the IBMRSEED downgrade lands a cleartext password.

---

## API (`:52500`)

Line-based TCP. One command per line, one response per line. JSON for structured data.

```bash
echo "ping" | nc -q1 127.0.0.1 52500                    # → pong
echo "get_screen_text" | nc -q1 127.0.0.1 52500          # → 24×80 grid
echo "ffw_reveal_hidden on" | nc -q1 127.0.0.1 52500     # → OK
echo "send_field 20 17 99 ENTER" | nc -q1 127.0.0.1 52500  # type 99, Enter
```

**~30 handlers:** `ping`, `get_screen_text`, `get_fields`, `get_pf_mask`, `list_aids`, `send_aid`, `send_attn`, `send_field`, `send_fields`, `send_raw_hex`, `ffw_unprotect/reveal_hidden/remove_numeric/high_visibility`, `ffw_status`, `ibmrseed_downgrade`, `devname_spoof`, `nego_status`, `get_captured_creds`, `mask_arm`, `mask_status`, `inject_word`, `log_count`, `refresh_screen`, `get_messages`, `get_strpccmd_alerts`, `tamper_map`, `get_hidden_content`, `clear_findings`.

### Multi-field inject — the full tampering attack

```bash
echo 'send_fields {"fields":[[20,19,"Y"],[9,21,"$0.01"]],"aid":"ENTER"}' | nc -q1 127.0.0.1 52500
```

Two SBA pairs in one packet: the legit Order field (`Y`) plus an injected write to the protected price position. The host can't tell which pair is "supposed" to be there.

---

## MCP server (37 tools)

For AI-driven testing. Wraps `:52500` in FastMCP stdio.

```json
{
  "mcpServers": {
    "hack5250": {
      "command": ".venv/bin/python",
      "args": ["MCPs/hack5250_mcp/hack5250_mcp.py"]
    }
  }
}
```

**Compound workflows:** `quick_recon`, `enable_all_ffw_hacks`, `attempt_attn_escape`, `select_menu_option`, **`tamper_protected_field`** (the combined legit-input + protected-write attack as one call).

---

## Why selective unprotect?

3270's protected bit just stops the cursor entering a field. Flip it, the host doesn't notice. **5250's BYPASS bit controls format-table membership.** Clearing it on every protected field turns 97 decorative output fields into tab stops. The emulator's format table goes from 1 input field to 98. The user presses ENTER, the emulator sends back 98 SBA pairs the host never asked for, and the host rejects.

So `unprotect` only fires on fields that are *also* `NONDISP`. Visible protected fields are decorative — not attack targets. Hidden protected fields are. The constraint reduced the byte-change count on the Mels Cargo menu from 100 to 4.

The SOH PF-mask rewrite was also removed — writing `FFFFFF` over the host's `000000` caused an X-SYSTEM emulator lock. The mask is still *read* (`get_pf_mask`, `get_masked_keys`); we just don't write it. Sending masked AIDs works regardless — the mask is advisory to the terminal, not enforced server-side.

---

## Live findings (Mels Cargo test app, 2026-04-08)

| # | Finding | Severity |
|---|---|---|
| 1 | Hidden option `99) Delete Order History` — `DSPATR(ND)` as access control. No auth check. Executed: `DELETED 00000 RECORDS`. | Critical |
| 2 | Protected-field tampering — SBA write to price field accepted, **`$0.01129.59` persisted to order database** (order #00002). | Critical |
| 3 | Supervisor PIN = `1337` (4-char field, brute-forced on 2nd guess). | High |
| 4 | Direct program invocation post-abend — type `MCMM` at blank screen, transaction restarts, no re-auth. | Medium |
| 5 | Hidden `Purchaseable: Y` flag in MCOR — control surface for ordering, masked from users. | Info |

The price tamper is the headline. Order History stored exactly what was injected.

---

## Protocol references

- **RFC 1205** — 5250 Telnet Interface (the 10-byte header)
- **RFC 2877** — 5250 Telnet Enhancements (`IBMRSEED`, `DEVNAME`)
- **RFC 4777** — IBM iSeries Telnet Enhancements (`IBMSENDCONFREC` Startup Response codes — the username oracle)
- **IBM SC30-3533-04** — 5494 Functions Reference (canonical 5250 datastream spec; not freely online)
- **IBM SC41-5715** — DDS Reference (PUTOVR, OVRDTA, RTNCSRLOC, subfile RRN)
- **IBM SC41-5407** — Display File Reference (QDSIGNON 178-byte buffer mandate)
- **Wireshark `packet-tn5250.c`** — the byte-layout reference this parser was built against

---

## See also

- [`hack3270`](https://github.com/gglessner/hack3270) — the tn3270 sibling
- [`hackterm-core`](https://github.com/gglessner/hackterm-core) — the shared `Protocol` ABC, `ProxyDaemon`, `Storage`, `EbcdicCodec` (vendored under `./hackterm-core/`; refresh with `scripts/update-vendored.sh`)

---

*"5250's format table is a contract."*
