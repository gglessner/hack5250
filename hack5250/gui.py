"""
hack5250 GUI — PySide6, 5 tabs.

Drives the Hack5250 orchestration object. Lifecycle:
    gui = Hack5250GUI(h)
    gui.run()   # blocks until window closed

run() does the same handshake the placeholder did (start_api → wait_for_emulator
→ connect_to_host) but wrapped in a Qt connection dialog, then builds the
main window and pumps h.tick() at 100Hz from a QTimer.

Five tabs (spec §4.4):
  1. Hack FFW          — checkboxes → set_ffw_*
  2. Inject AID        — button grid → send_aid / send_attn
  3. Negotiation       — IBMRSEED downgrade + DEVNAME spoof
  4. Inject Into Fields — mask-template wordlist injection
  5. Logs              — incremental SQLite log viewer

Plus a right-side dock that always shows captured credentials in red.
"""
import sys
import signal
import time
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QDockWidget,
    QVBoxLayout, QHBoxLayout, QGridLayout, QGroupBox, QSplitter,
    QLabel, QPushButton, QCheckBox,
    QLineEdit, QComboBox, QListWidget, QTableWidget, QTableWidgetItem,
    QPlainTextEdit, QHeaderView,
)


# Wordlist directory: hack5250/injections/ — sibling of this package dir
INJECTIONS_DIR = Path(__file__).resolve().parent.parent / "injections"

# Dark theme — adapted from hack3270's DARK_STYLE (gui.py:88-249).
# Blue accent #0078d4, rounded corners, custom checkbox indicators,
# bold blue GroupBox titles. This is what makes the tools look related.
_STYLE = """
QMainWindow, QWidget {
    background-color: #1e1e1e;
    color: #d4d4d4;
    font-family: 'Segoe UI', sans-serif;
    font-size: 13px;
}
QTabWidget::pane {
    border: 1px solid #3c3c3c;
    background-color: #252526;
    border-radius: 4px;
}
QTabBar::tab {
    background-color: #2d2d2d;
    color: #808080;
    padding: 8px 16px;
    margin-right: 2px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}
QTabBar::tab:selected {
    background-color: #1e1e1e;
    color: #ffffff;
    border-bottom: 2px solid #0078d4;
}
QTabBar::tab:hover:!selected {
    background-color: #383838;
}
QPushButton {
    background-color: #0078d4;
    color: white;
    border: none;
    padding: 8px 16px;
    border-radius: 4px;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #1084d8;
}
QPushButton:pressed {
    background-color: #006cbd;
}
QPushButton:disabled {
    background-color: #3c3c3c;
    color: #808080;
}
QPushButton[class="danger"] {
    background-color: #d32f2f;
}
QPushButton[class="danger"]:hover {
    background-color: #e53935;
}
QPushButton[class="success"] {
    background-color: #388e3c;
}
QPushButton[class="success"]:hover {
    background-color: #43a047;
}
QPushButton[class="compact"] {
    padding: 6px 8px;
    min-width: 0px;
}
QCheckBox {
    spacing: 8px;
    color: #d4d4d4;
}
QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border-radius: 3px;
    border: 2px solid #5c5c5c;
    background-color: #2d2d2d;
}
QCheckBox::indicator:checked {
    background-color: #0078d4;
    border-color: #0078d4;
}
QCheckBox::indicator:hover {
    border-color: #0078d4;
}
QComboBox {
    background-color: #3c3c3c;
    border: 1px solid #5c5c5c;
    border-radius: 4px;
    padding: 6px 12px;
    min-width: 100px;
}
QComboBox:hover {
    border-color: #0078d4;
}
QComboBox::drop-down {
    border: none;
    width: 20px;
}
QComboBox QAbstractItemView {
    background-color: #2d2d2d;
    border: 1px solid #5c5c5c;
    selection-background-color: #0078d4;
}
QLineEdit {
    background-color: #3c3c3c;
    border: 1px solid #5c5c5c;
    border-radius: 4px;
    padding: 6px 12px;
}
QLineEdit:focus {
    border-color: #0078d4;
}
QTableWidget, QListWidget {
    background-color: #1e1e1e;
    border: 1px solid #3c3c3c;
    border-radius: 4px;
    alternate-background-color: #252526;
}
QTableWidget::item, QListWidget::item {
    padding: 4px;
}
QTableWidget::item:selected, QListWidget::item:selected {
    background-color: #0078d4;
}
QTableWidget::item:hover:!selected, QListWidget::item:hover:!selected {
    background-color: #2a2d2e;
}
QHeaderView::section {
    background-color: #2d2d2d;
    color: #d4d4d4;
    padding: 8px;
    border: none;
    border-right: 1px solid #3c3c3c;
    font-weight: bold;
}
QPlainTextEdit {
    background-color: #1e1e1e;
    color: #d4d4d4;
    border: 1px solid #3c3c3c;
    border-radius: 4px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
}
QGroupBox {
    font-weight: bold;
    border: 1px solid #3c3c3c;
    border-radius: 4px;
    margin-top: 12px;
    padding-top: 12px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
    color: #0078d4;
}
QScrollBar:vertical {
    background-color: #1e1e1e;
    width: 12px;
    border-radius: 6px;
}
QScrollBar::handle:vertical {
    background-color: #5c5c5c;
    border-radius: 6px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover {
    background-color: #808080;
}
QSplitter::handle {
    background-color: #3c3c3c;
}
QLabel[class="status-ready"] { color: #4caf50; }
QLabel[class="status-warning"] { color: #ff9800; }
QLabel[class="status-error"] { color: #f44336; }
QLabel[class="status-info"] { color: #2196f3; }
QLabel[class="header"] {
    font-size: 14px;
    font-weight: bold;
    color: #0078d4;
}
"""


# ======================================================================
# Public façade
# ======================================================================

class Hack5250GUI:
    """Public entry point. Same contract as the placeholder: __init__(h) + run()."""

    def __init__(self, h):
        self.h = h
        self.app = QApplication.instance() or QApplication(sys.argv)
        self.app.setStyleSheet(_STYLE)
        self.window = None

    def run(self):
        h = self.h

        # Ctrl-C handling: Qt's event loop catches KeyboardInterrupt in
        # slot callbacks (the QTimer-driven tick) and prints the traceback
        # instead of propagating. Install SIGINT → quit() so Ctrl-C exits
        # cleanly through the finally. Also covers the blocking accept()
        # phase before the Qt loop starts.
        prev_sigint = signal.signal(signal.SIGINT, lambda *_: self.app.quit())

        try:
            # --- 1. API socket --------------------------------------------
            h.start_api()

            # --- 2. Connection handshake (modal dialog) ------------------
            listen = h.daemon.listen_addr
            target = h.daemon.target_addr
            dlg = _ConnectionDialog(
                f"Proxy listening on {listen[0]}:{listen[1]}\n"
                f"Connect your tn5250 emulator now."
            )
            dlg.show()
            QApplication.processEvents()

            try:
                h.wait_for_emulator()  # blocking accept()
            except OSError:
                # Ctrl-C during accept() — listener closed by quit() handler
                # racing with shutdown, or socket error. Either way: bail.
                return
            dlg.set_message(f"Emulator connected.\nConnecting to IBM i at {target[0]}:{target[1]} ...")

            h.connect_to_host()
            dlg.close()

            # --- 3. Main window -------------------------------------------
            self.window = _MainWindow(h)
            self.window.show()

            # --- 4. Tick the proxy at 100Hz ------------------------------
            tick_timer = QTimer(self.window)
            tick_timer.timeout.connect(h.tick)
            tick_timer.start(10)

            # --- 5. UI refresh: creds dock, masked-keys label, logs -----
            refresh_timer = QTimer(self.window)
            refresh_timer.timeout.connect(self.window.refresh)
            refresh_timer.start(1500)

            # --- 6. Block -------------------------------------------------
            self.app.exec()
        finally:
            signal.signal(signal.SIGINT, prev_sigint)
            h.shutdown()


# ======================================================================
# Connection dialog
# ======================================================================

class _ConnectionDialog(QWidget):
    """Modal-ish dialog shown during the wait_for_emulator block.
    Mirrors hack3270's ConnectionDialog but trimmed."""

    def __init__(self, message):
        super().__init__()
        self.setWindowTitle("hack5250 — connecting")
        self.setStyleSheet(_STYLE)
        screen = QApplication.primaryScreen().geometry()
        w = screen.width() // 2
        self.setFixedSize(w, 100)
        self.move((screen.width() - w) // 2, 0)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        self.label = QLabel(message)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setWordWrap(True)
        self.label.setFont(QFont("", 11))
        layout.addWidget(self.label)

    def set_message(self, msg):
        self.label.setText(msg)
        QApplication.processEvents()


# ======================================================================
# Main window
# ======================================================================

class _MainWindow(QMainWindow):
    def __init__(self, h):
        super().__init__()
        self.h = h
        self.setWindowTitle("hack5250 — IBM i MITM Proxy")

        screen = QApplication.primaryScreen().geometry()
        self._screen_width = screen.width()
        # Per-tab heights — same "full-width strip" model as hack3270.
        self._tab_heights = {
            0: 200,   # Hack FFW
            1: 250,   # Inject AID
            2: 400,   # Negotiation
            3: 180,   # Inject Into Fields
            4: 525,   # Logs
        }

        # Refs filled by tab builders, polled by refresh()
        self._masked_label = None
        self._creds_table = None
        self._creds_dock_list = None
        self._logs_table = None
        self._logs_detail = None
        self._logs_last_id = 0
        self._inject_status = None

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_ffw_tab(),    "Hack FFW")
        self.tabs.addTab(self._build_aid_tab(),    "Inject AID")
        self.tabs.addTab(self._build_nego_tab(),   "Negotiation")
        self.tabs.addTab(self._build_inject_tab(), "Inject Into Fields")
        self.tabs.addTab(self._build_logs_tab(),   "Logs")
        self.tabs.currentChanged.connect(self._on_tab_changed)
        self.setCentralWidget(self.tabs)

        self._build_creds_dock()

        self.resize(self._screen_width, self._tab_heights[0])
        self.setMinimumWidth(self._screen_width)
        self.setMinimumHeight(100)
        self.move(0, 0)

    def _on_tab_changed(self, index: int) -> None:
        self.resize(self._screen_width, self._tab_heights.get(index, 525))

    # ------------------------------------------------------------------
    # Tab 1: Hack FFW — layout matches hack3270's "Hack Field Attributes"
    #
    # Master ON/OFF button + horizontal QGroupBox clusters. Checkboxes
    # default-checked; the master button is what actually arms/disarms.
    # When ON, it pushes whichever boxes are checked onto the daemon.
    # ------------------------------------------------------------------
    def _build_ffw_tab(self):
        w = QWidget()
        layout = QHBoxLayout(w)
        layout.setSpacing(20)
        layout.setContentsMargins(10, 10, 10, 10)

        # --- Master ON/OFF button group --------------------------------
        # hack3270 ref: gui.py:464-472. Same widget choices, same sizing.
        btn_group = QGroupBox("Hack FFW")
        btn_layout = QVBoxLayout(btn_group)
        self._ffw_btn = QPushButton("OFF")
        self._ffw_btn.setProperty("class", "danger")  # red, matches hack3270 L467
        self._ffw_btn.setMinimumWidth(100)
        self._ffw_btn.clicked.connect(self._ffw_btn_pressed)
        btn_layout.addWidget(self._ffw_btn)
        btn_layout.addStretch()
        layout.addWidget(btn_group)

        # --- Field Options group ---------------------------------------
        # All default-checked, like hack3270. unprotect is now SELECTIVE
        # (only fires on hidden fields — see tn5250.py:_mutate_sf), so
        # it's safe to default ON. Live test 2026-04-08: unconditional
        # unprotect broke navigation; selective unprotect changes 7 bytes
        # instead of 100 on the Mels Cargo menu.
        opts_group = QGroupBox("Field Options")
        opts_layout = QVBoxLayout(opts_group)
        self._ffw_unprot_cb = QCheckBox("Disable Field Protection (on hidden fields)")
        self._ffw_unprot_cb.setChecked(True)
        self._ffw_unprot_cb.setToolTip(
            "Clears FFW BYPASS only on fields that are ALSO non-display.\n"
            "Visible protected fields (decorative output) are left alone\n"
            "to avoid breaking the format table contract with the host."
        )
        self._ffw_reveal_cb = QCheckBox("Enable Hidden Fields (NONDISP \u2192 visible)")
        self._ffw_reveal_cb.setChecked(True)
        self._ffw_numeric_cb = QCheckBox("Remove Numeric/Mandatory Restrictions")
        self._ffw_numeric_cb.setChecked(True)
        for cb in (self._ffw_unprot_cb, self._ffw_reveal_cb, self._ffw_numeric_cb):
            cb.stateChanged.connect(self._ffw_apply)
            opts_layout.addWidget(cb)
        opts_layout.addStretch()
        layout.addWidget(opts_group)

        # --- SOH PF-mask info (read-only) ------------------------------
        # The SOH mask rewrite was REMOVED — it caused X-SYSTEM lock on
        # the Java emulator (live finding 2026-04-08). The mask is still
        # READ via parse() and shown on the Inject AID tab ("Masked keys:").
        # Sending masked AIDs works regardless — the host's mask is
        # advisory to the terminal, not enforced server-side.
        soh_group = QGroupBox("SOH PF-Key Mask")
        soh_layout = QVBoxLayout(soh_group)
        self._ffw_soh_label = QLabel("(see Inject AID tab\nfor masked keys)")
        self._ffw_soh_label.setStyleSheet("color: #888; font-size: 11px;")
        soh_layout.addWidget(self._ffw_soh_label)
        soh_note = QLabel("Mask is read-only.\nRewriting it caused\nX-SYSTEM lock — removed.")
        soh_note.setStyleSheet("color: #888; font-size: 10px;")
        soh_layout.addWidget(soh_note)
        soh_layout.addStretch()
        layout.addWidget(soh_group)

        # --- Hidden Field Highlighting group (matches hack3270) --------
        hl_group = QGroupBox("Hidden Field Highlighting")
        hl_layout = QVBoxLayout(hl_group)
        self._ffw_hivis_cb = QCheckBox("High Visibility (white)")
        self._ffw_hivis_cb.setChecked(True)
        self._ffw_hivis_cb.stateChanged.connect(self._ffw_apply)
        hl_layout.addWidget(self._ffw_hivis_cb)
        hl_note = QLabel("Default: green (0x20)\nHigh-vis: white (0x22)")
        hl_note.setStyleSheet("color: #888; font-size: 10px;")
        hl_layout.addWidget(hl_note)
        hl_layout.addStretch()
        layout.addWidget(hl_group)

        # State
        self._ffw_active = False
        return w

    def _ffw_btn_pressed(self):
        """Master toggle. hack3270 semantics (gui.py:2236-2249):
        OFF = red (danger) — attacks NOT armed, this is the safe state
        ON  = green (success) — attacks ARE armed, hacking active
        """
        self._ffw_active = not self._ffw_active
        btn = self._ffw_btn
        if self._ffw_active:
            btn.setText("ON")
            btn.setProperty("class", "success")
        else:
            btn.setText("OFF")
            btn.setProperty("class", "danger")
        # Qt needs explicit re-polish to re-evaluate property-based selectors.
        btn.style().unpolish(btn)
        btn.style().polish(btn)
        self._ffw_apply()

    def _ffw_apply(self):
        """Push checkbox state to daemon — but only if master is ON.
        When master is OFF, all toggles go to False regardless of checkboxes.
        This matches hack3270's behavior: you can pre-configure which
        attacks fire, then arm/disarm with one button.

        ONE refresh at the end — not per-setter. 232bd8b put _resend_last()
        in each setter, causing 4 screens in <1ms. Emulator's format-table
        rebuild got interrupted; input stopped flowing.
        """
        on = self._ffw_active
        self.h.set_ffw_unprotect(on and self._ffw_unprot_cb.isChecked())
        self.h.set_ffw_reveal_hidden(on and self._ffw_reveal_cb.isChecked())
        self.h.set_ffw_remove_numeric(on and self._ffw_numeric_cb.isChecked())
        self.h.set_ffw_high_visibility(on and self._ffw_hivis_cb.isChecked())
        # Single refresh AFTER all flags are set
        self.h.refresh_screen()

    # ------------------------------------------------------------------
    # Tab 2: Inject AID
    # ------------------------------------------------------------------
    def _build_aid_tab(self):
        w = QWidget()
        outer = QHBoxLayout(w)
        outer.setContentsMargins(10, 10, 10, 10)

        # --- Left: button grid ----
        grid_widget = QWidget()
        grid = QGridLayout(grid_widget)
        grid.setSpacing(4)

        # Row layout per spec. Only place buttons for keys actually in aid_table.
        rows = [
            [f"F{i}" for i in range(1, 13)],
            [f"F{i}" for i in range(13, 25)],
            ["ENTER", "ROLLUP", "ROLLDN", "HELP", "PRINT", "CLEAR", "RECBS", "AUTO"],
            ["PA1", "PA2", "PA3"],
        ]
        for r, names in enumerate(rows):
            for c, name in enumerate(names):
                if name not in self.h.protocol.aid_table:
                    continue
                btn = QPushButton(name)
                btn.setProperty("class", "compact")  # tighter padding for 12-col grid
                btn.setMinimumWidth(56)
                # Capture name in default arg — classic loop-closure trap.
                btn.clicked.connect(lambda _=False, n=name: self.h.send_aid(n))
                grid.addWidget(btn, r, c)

        # Masked keys + send-all button
        self._masked_label = QLabel("Masked keys: (no screen yet)")
        self._masked_label.setStyleSheet("color: #ce9178;")
        grid.addWidget(self._masked_label, 4, 0, 1, 12)

        send_masked = QPushButton("Send All Masked Keys")
        send_masked.clicked.connect(self._send_all_masked)
        grid.addWidget(send_masked, 5, 0, 1, 4)

        grid.setRowStretch(6, 1)
        outer.addWidget(grid_widget, stretch=4)

        # --- Right: ATTN side panel ----
        side = QVBoxLayout()
        attn = QPushButton("ATTN")
        attn.setProperty("class", "danger")  # red — ATTN is the headline 5250 attack
        attn.setMinimumHeight(120)
        attn.setStyleSheet("font-size: 18px;")  # only override font; color from class
        attn.clicked.connect(self.h.send_attn)
        side.addWidget(attn)
        hint = QLabel("ATTN → Op Assist\n→ F9 → CL prompt\n(Silent Signal escape)")
        hint.setStyleSheet("color: #888; font-size: 10px;")
        side.addWidget(hint)
        side.addStretch()
        outer.addLayout(side, stretch=1)

        return w

    def _send_all_masked(self):
        for k in self.h.get_masked_keys():
            self.h.send_aid(k)

    # ------------------------------------------------------------------
    # Tab 3: Negotiation
    # ------------------------------------------------------------------
    def _build_nego_tab(self):
        # Layout matches hack3270's Negotiation: horizontal QGroupBox row,
        # full-width status line below.
        container = QWidget()
        outer = QVBoxLayout(container)
        outer.setContentsMargins(10, 10, 10, 10)

        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(20)

        # ===== IBMRSEED group =================================================
        seed_box = QGroupBox("IBMRSEED Downgrade")
        sv = QVBoxLayout(seed_box)

        cb = QCheckBox("Strip IBMRSEED (force cleartext password)")
        sv.addWidget(cb)

        warn = QLabel("Captured creds appear AFTER emulator reconnects")
        warn.setStyleSheet("color: #ce9178; font-style: italic;")
        warn.setWordWrap(True)
        sv.addWidget(warn)

        # creds: (user, password) tuples — no timestamp in the data, so 2 cols
        self._creds_table = QTableWidget(0, 2)
        self._creds_table.setHorizontalHeaderLabels(["User", "Password"])
        self._creds_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._creds_table.setEditTriggers(QTableWidget.NoEditTriggers)
        sv.addWidget(self._creds_table)

        layout.addWidget(seed_box, stretch=1)

        # ===== DEVNAME group ==================================================
        dev_box = QGroupBox("DEVNAME Spoof")
        dv = QVBoxLayout(dev_box)

        # Manual entry row
        man_row = QHBoxLayout()
        dev_entry = QLineEdit()
        dev_entry.setPlaceholderText("device name (e.g. QPADEV0001)")
        man_row.addWidget(dev_entry, stretch=1)
        set_btn = QPushButton("Set")
        man_row.addWidget(set_btn)
        clr_btn = QPushButton("Clear")
        man_row.addWidget(clr_btn)
        dv.addLayout(man_row)

        # Wordlist row
        wl_row = QHBoxLayout()
        wl_row.addWidget(QLabel("From list:"))
        dev_dropdown = QComboBox()
        dev_words = _load_wordlist("device-names.txt")
        dev_dropdown.addItems(dev_words)
        wl_row.addWidget(dev_dropdown, stretch=1)
        next_btn = QPushButton("Try Next from List")
        next_btn.setProperty("class", "success")
        wl_row.addWidget(next_btn)
        dv.addLayout(wl_row)
        dv.addStretch()

        layout.addWidget(dev_box, stretch=1)

        outer.addWidget(row)

        # ===== Status line (full width, updates on every action) =============
        self._nego_status = QLabel("Ready.")
        self._nego_status.setStyleSheet("color: #888;")
        outer.addWidget(self._nego_status)

        # ----- Wiring (after _nego_status exists) ---------------------------
        def _seed_toggled(on):
            self.h.set_ibmrseed_downgrade(on)
            if on:
                self._nego_status.setText(
                    "IBMRSEED downgrade armed. Reconnect emulator to capture cleartext."
                )
            else:
                self._nego_status.setText("IBMRSEED downgrade off.")
        cb.toggled.connect(_seed_toggled)

        def _set_dev():
            name = dev_entry.text().strip() or None
            self.h.set_devname_spoof(name)
            if name:
                self._nego_status.setText(
                    f"DEVNAME spoof set: {name}. Reconnect emulator to apply."
                )
            else:
                self._nego_status.setText("DEVNAME spoof cleared.")
        set_btn.clicked.connect(_set_dev)

        def _clear_dev():
            self.h.set_devname_spoof(None)
            dev_entry.clear()
            self._nego_status.setText("DEVNAME spoof cleared.")
        clr_btn.clicked.connect(_clear_dev)

        dev_idx = [0]  # mutable closure cell

        def _try_next():
            if not dev_words:
                return
            name = dev_words[dev_idx[0] % len(dev_words)]
            dev_idx[0] += 1
            dev_entry.setText(name)
            dev_dropdown.setCurrentText(name)
            self.h.set_devname_spoof(name)
            self._nego_status.setText(
                f"DEVNAME spoof set: {name}. Reconnect emulator to apply."
            )
        next_btn.clicked.connect(_try_next)

        return container

    # ------------------------------------------------------------------
    # Tab 4: Inject Into Fields
    # ------------------------------------------------------------------
    def _build_inject_tab(self):
        # Layout matches hack3270's Inject Into Fields idiom: two flat
        # horizontal rows (control bar + options bar). No GroupBoxes.
        # Mode is a QComboBox (not radio) — see hack3270_libs/gui.py:611-613.
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(10, 10, 10, 10)

        # ===== Row 1: control bar (arm + status + inject) ==================
        ctrl = QHBoxLayout()

        sb = QPushButton("Arm Mask Capture")
        ctrl.addWidget(sb)

        self._inject_status = QLabel("Not armed.")
        self._inject_status.setStyleSheet("color: #888;")
        ctrl.addWidget(self._inject_status)
        ctrl.addStretch()

        inj_btn = QPushButton("Inject Next")
        inj_btn.setProperty("class", "success")
        ctrl.addWidget(inj_btn)

        layout.addLayout(ctrl)

        # ===== Row 2: options bar (wordlist + mode + progress) =============
        opts = QHBoxLayout()

        opts.addWidget(QLabel("Wordlist:"))
        wl_combo = QComboBox()
        files = sorted(p.name for p in INJECTIONS_DIR.glob("*.txt")) if INJECTIONS_DIR.is_dir() else []
        wl_combo.addItems(files)
        if "cl-commands.txt" in files:
            wl_combo.setCurrentText("cl-commands.txt")
        opts.addWidget(wl_combo, stretch=1)

        opts.addSpacing(20)
        opts.addWidget(QLabel("Mode:"))
        self._inject_mode = QComboBox()
        self._inject_mode.addItems(["TRUNC", "SKIP", "OVERFLOW"])
        opts.addWidget(self._inject_mode)

        opts.addSpacing(20)
        progress = QLabel("0 / 0 entries")
        opts.addWidget(progress)

        layout.addLayout(opts)

        # ----- Wiring ------------------------------------------------------
        def _arm():
            self.h.arm_mask_capture()
            self._inject_status.setText(
                "ARMED — type **** in target field, press Enter"
            )
            self._inject_status.setStyleSheet("color: #d7ba7d;")
        sb.clicked.connect(_arm)

        # State: cached words + cursor; reload on file change.
        state = {"words": [], "idx": 0, "file": None}

        def _ensure_loaded():
            fname = wl_combo.currentText()
            if fname and fname != state["file"]:
                state["words"] = _load_wordlist(fname)
                state["idx"] = 0
                state["file"] = fname
                progress.setText(f"0 / {len(state['words'])} entries")

        def _inject_next():
            _ensure_loaded()
            if not self.h.is_mask_ready():
                progress.setText("Mask not captured — arm + type **** first")
                return
            if state["idx"] >= len(state["words"]):
                progress.setText(f"Done: {len(state['words'])} / {len(state['words'])} entries")
                return
            word = state["words"][state["idx"]]
            mode = self._inject_mode.currentText()
            self.h.inject_word(word, mode)
            state["idx"] += 1
            progress.setText(f"{state['idx']} / {len(state['words'])} entries  (last: {word})")

        inj_btn.clicked.connect(_inject_next)
        wl_combo.currentTextChanged.connect(lambda _: _ensure_loaded())
        _ensure_loaded()

        layout.addStretch()
        return w

    # ------------------------------------------------------------------
    # Tab 5: Logs
    # ------------------------------------------------------------------
    def _build_logs_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)

        split = QSplitter(Qt.Vertical)

        # all_logs() returns (ID, TIMESTAMP, C_S, NOTES, DATA_LEN, RAW_DATA)
        self._logs_table = QTableWidget(0, 5)
        self._logs_table.setHorizontalHeaderLabels(["ID", "Time", "Dir", "Notes", "Len"])
        hdr = self._logs_table.horizontalHeader()
        hdr.setSectionResizeMode(3, QHeaderView.Stretch)  # Notes stretches
        self._logs_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._logs_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._logs_table.setAlternatingRowColors(True)
        self._logs_table.setSortingEnabled(True)
        self._logs_table.itemSelectionChanged.connect(self._show_log_detail)
        split.addWidget(self._logs_table)

        self._logs_detail = QPlainTextEdit()
        self._logs_detail.setReadOnly(True)
        self._logs_detail.setFont(QFont("Monospace", 9))
        split.addWidget(self._logs_detail)

        split.setSizes([400, 200])
        layout.addWidget(split)
        return w

    def _show_log_detail(self):
        sel = self._logs_table.selectedItems()
        if not sel:
            return
        log_id = int(self._logs_table.item(sel[0].row(), 0).text())
        raw = self.h.storage.get_raw(log_id)
        if raw is None:
            return
        hexdump = raw.hex(" ", 1)
        try:
            text = self.h.codec.decode(raw)
        except Exception:
            text = "(decode failed)"
        self._logs_detail.setPlainText(
            f"--- HEX ({len(raw)} bytes) ---\n{hexdump}\n\n--- EBCDIC ---\n{text}"
        )

    # ------------------------------------------------------------------
    # Dock: captured credentials
    # ------------------------------------------------------------------
    def _build_creds_dock(self):
        dock = QDockWidget("Captured Credentials", self)
        dock.setAllowedAreas(Qt.RightDockWidgetArea | Qt.LeftDockWidgetArea)
        self._creds_dock_list = QListWidget()
        self._creds_dock_list.setStyleSheet(
            "color: #ff5555; font-weight: bold; font-family: Monospace;"
        )
        dock.setWidget(self._creds_dock_list)
        dock.setMinimumWidth(220)
        self.addDockWidget(Qt.RightDockWidgetArea, dock)

    # ------------------------------------------------------------------
    # Periodic refresh (1.5s)
    # ------------------------------------------------------------------
    def refresh(self):
        # --- Masked keys label ---
        if self._masked_label is not None:
            keys = self.h.get_masked_keys()
            self._masked_label.setText(
                "Masked keys: " + (", ".join(keys) if keys else "(none)")
            )

        # --- Inject tab: detect mask-ready transition ---
        if self._inject_status is not None and self.h.is_mask_ready():
            inj = self.h.injector
            txt = (f"Mask captured: len={inj.mask_len}  "
                   f"pre={len(inj.preamble)}B  post={len(inj.postamble)}B")
            if self._inject_status.text() != txt:
                self._inject_status.setText(txt)
                self._inject_status.setStyleSheet("color: #4ec9b0;")

        # --- Creds: dock list + table (small N, full rebuild fine) ---
        creds = self.h.captured_creds
        if self._creds_dock_list is not None and self._creds_dock_list.count() != len(creds):
            self._creds_dock_list.clear()
            for u, p in creds:
                self._creds_dock_list.addItem(f"{u} : {p}")
        if self._creds_table is not None and self._creds_table.rowCount() != len(creds):
            self._creds_table.setRowCount(len(creds))
            for i, (u, p) in enumerate(creds):
                self._creds_table.setItem(i, 0, QTableWidgetItem(u))
                self._creds_table.setItem(i, 1, QTableWidgetItem(p))

        # --- Logs: incremental — only fetch rows with ID > last seen ---
        if self._logs_table is not None:
            new_rows = self.h.storage.all_logs(start=self._logs_last_id)
            if new_rows:
                tbl = self._logs_table
                # Sorting must be off during bulk insert — Qt re-sorts on each
                # setItem otherwise, scrambling row indices mid-loop.
                was_sorting = tbl.isSortingEnabled()
                tbl.setSortingEnabled(False)
                base = tbl.rowCount()
                tbl.setRowCount(base + len(new_rows))
                for off, row in enumerate(new_rows):
                    # row = (ID, TIMESTAMP, C_S, NOTES, DATA_LEN, RAW_DATA)
                    rid, ts, cs, notes, dlen = row[0], row[1], row[2], row[3], row[4]
                    r = base + off
                    tbl.setItem(r, 0, QTableWidgetItem(str(rid)))
                    tbl.setItem(r, 1, QTableWidgetItem(_fmt_ts(ts)))
                    tbl.setItem(r, 2, QTableWidgetItem(str(cs)))
                    tbl.setItem(r, 3, QTableWidgetItem(str(notes or "")))
                    tbl.setItem(r, 4, QTableWidgetItem(str(dlen)))
                    self._logs_last_id = max(self._logs_last_id, rid)
                tbl.setSortingEnabled(was_sorting)

    # ------------------------------------------------------------------
    def closeEvent(self, event):
        # Timers are children → die automatically. shutdown() runs in run()'s finally.
        event.accept()


# ======================================================================
# Helpers
# ======================================================================

def _load_wordlist(filename: str) -> list[str]:
    """Read INJECTIONS_DIR/<filename>, strip blanks and # comments."""
    path = INJECTIONS_DIR / filename
    if not path.is_file():
        return []
    out = []
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if s and not s.startswith("#"):
                out.append(s)
    return out


def _fmt_ts(ts) -> str:
    """Storage stores TIMESTAMP as str(time.time()). Render as HH:MM:SS."""
    try:
        return time.strftime("%H:%M:%S", time.localtime(float(ts)))
    except (ValueError, TypeError):
        return str(ts)
