"""
5250 protocol constants.

Sources:
  - RFC 1205 (5250 Telnet Interface) — 10-byte header, opcodes
  - RFC 2877 (5250 Telnet Enhancements) — NEW-ENVIRON USERVARs (IBMRSEED, DEVNAME)
  - Wireshark packet-tn5250.c — FFW/FCW bit layouts, AID values
  - lib5250/codes5250.h — command/order opcodes, screen attributes
  - IBM SC30-3533-04 (5494 Functions Reference) — canonical, not freely online

Where sources disagree, Wireshark wins (it's tested against real traffic).
"""

# === 10-byte SNA-style record header (RFC 1205 §3) ===
#
# CORRECTED 2026-04-08 against real emulator capture. Previous version
# had a one-byte alignment error (offsets 5-9 all shifted left).
#
# Offset 0-1: record length (big-endian, includes header, EXCLUDES IAC EOR)
# Offset 2-3: record type (0x12A0 = General Data Stream)
# Offset 4-5: reserved (TWO bytes — RFC says 1, real packets have 2)
# Offset 6:   variable header length (always 0x04)
# Offset 7-8: flags (16-bit; bit 7 of byte 7 = ERR, bit 6 = ATN attention)
# Offset 9:   opcode
HDR_LEN = 10
GDS_TYPE = 0x12A0

OPCODE_NONE          = 0x00
OPCODE_INVITE        = 0x01
OPCODE_OUTPUT        = 0x02
OPCODE_PUT_GET       = 0x03
OPCODE_SAVE_SCREEN   = 0x04
OPCODE_RESTORE_SCREEN= 0x05
OPCODE_READ_IMMED    = 0x06
OPCODE_READ_SCREEN   = 0x07

# Header flag bits (byte 7 — high byte of 16-bit flags at offsets 7-8)
HDR_FLAG_ERR = 0x80
HDR_FLAG_ATN = 0x40   # ATTN key — used for menu escape

# === Datastream layer (after header) ===
# Commands are preceded by ESC (0x04). Multiple ESC+CMD pairs per record.
ESC = 0x04

# Commands (lib5250/codes5250.h)
CMD_WRITE_TO_DISPLAY  = 0x11
CMD_CLEAR_UNIT        = 0x40
CMD_CLEAR_UNIT_ALT    = 0x20
CMD_CLEAR_FORMAT_TBL  = 0x50
CMD_READ_INPUT_FIELDS = 0x42
CMD_READ_MDT_FIELDS   = 0x52
CMD_READ_MDT_ALT      = 0x82
CMD_READ_SCREEN_IMMED = 0x62
CMD_SAVE_SCREEN       = 0x02
CMD_RESTORE_SCREEN    = 0x12
CMD_WRITE_ERROR_CODE  = 0x21
CMD_WRITE_STRUCTURED  = 0xF3
CMD_ROLL              = 0x23

# === Orders (inside Write to Display, after CC1+CC2 control bytes) ===
ORD_SOH = 0x01    # Start of Header: len(1) + flags + resv + err_row + pf_mask(3)
ORD_RA  = 0x02    # Repeat to Address: row(1) + col(1) + char(1)
ORD_EA  = 0x03    # Erase to Address: row(1) + col(1) + attr(1)
ORD_TD  = 0x10    # Transparent Data: len(2) + raw bytes (DO NOT PARSE)
ORD_SBA = 0x11    # Set Buffer Address: row(1) + col(1)
                  # NOTE: same byte as CMD_WRITE_TO_DISPLAY — context disambiguates
ORD_WEA = 0x12    # Write Extended Attribute
ORD_IC  = 0x13    # Insert Cursor: row(1) + col(1)
ORD_MC  = 0x14    # Move Cursor: row(1) + col(1)
ORD_WDSF= 0x15    # Write to Display Structured Field
ORD_SF  = 0x1D    # Start of Field — see FFW structure below
                  # NOTE: same byte as 3270 SF, but 5250 follows with FFW+attr+len

# === Start of Field structure ===
# ORD_SF (0x1D) is followed by:
#   [FFW: 2 bytes]   — present iff (word & 0xC000) == 0x4000
#   [FCW: 2 bytes]*  — zero or more, present iff (word & 0xC000) == 0x8000
#   screen_attr: 1 byte (0x20-0x3F)
#   field_length: 2 bytes (big-endian)
#
# An "output-only" field (display text, no input) has NO FFW — goes straight
# to attr+len. The FFW marker bits are how you tell.

# === Field Format Word (16 bits, big-endian) ===
FFW_ID         = 0x4000
FFW_ID_MASK    = 0xC000   # top 2 bits: 01=FFW, 10=FCW, else not-a-format-word
FFW_BYPASS     = 0x2000   # ← unprotect target: clear this bit
FFW_DUP        = 0x1000   # dup-key enabled
FFW_MDT        = 0x0800   # modified data tag
FFW_SHIFT_MASK = 0x0700   # ← remove_numeric target: zero these bits
                          #   000=alpha-shift  001=alpha-only  010=numeric-shift
                          #   011=numeric-only 100=katakana    101=digits-only
                          #   110=I/O          111=signed-numeric
FFW_AUTO_ENTER = 0x0080   # auto-enter when field exited
FFW_FER        = 0x0040   # field-exit-required (annoying when fuzzing — clear it)
FFW_MONOCASE   = 0x0020   # uppercase translation
FFW_RESERVED   = 0x0010
FFW_MAND_ENTRY = 0x0008   # mandatory entry
FFW_ADJUST_MASK= 0x0007   # 000=none 101=right-zero 110=right-blank 111=mand-fill

# Numeric-only shift values (FFW_SHIFT_MASK matches)
SHIFT_NUMERIC_ONLY  = 0x0300
SHIFT_DIGITS_ONLY   = 0x0500
SHIFT_SIGNED_NUMERIC= 0x0700

# === Field Control Word (16 bits, optional, may repeat) ===
FCW_ID      = 0x8000
FCW_ID_MASK = 0xC000
# FCW types (resequencing, magstripe, ideographic, etc.) — not needed for attacks

# FCW self-check types (terminal-side validation — strip target)
# Source: lib5250/codes5250.h, Wireshark packet-tn5250.c
FCW_SELFCHECK_MOD10 = 0xB1A0    # Luhn check digit
FCW_SELFCHECK_MOD11 = 0xB140    # Mod-11 check digit
FCW_NOOP            = 0x8000    # Bare FCW marker — emulators skip unknown types

# === Screen attribute byte (range 0x20-0x3F) ===
# Bit layout: 001x_xxxx (top bits 001 mark it as an attribute)
ATTR_GREEN     = 0x20
ATTR_GREEN_RI  = 0x21    # reverse image
ATTR_WHITE     = 0x22
ATTR_WHITE_RI  = 0x23
ATTR_GREEN_UL  = 0x24
ATTR_GREEN_ULI = 0x25
ATTR_WHITE_UL  = 0x26
ATTR_NONDISP   = 0x27    # ← reveal_hidden target: rewrite to ATTR_GREEN/WHITE
ATTR_RED       = 0x28
ATTR_RED_RI    = 0x29
ATTR_RED_BLINK = 0x2A
ATTR_RED_RB    = 0x2B
ATTR_RED_UL    = 0x2C
ATTR_RED_ULI   = 0x2D
ATTR_RED_ULB   = 0x2E
ATTR_NONDISP2  = 0x2F    # alternate non-display
ATTR_TURQ_CS   = 0x30
ATTR_TURQ_CSRI = 0x31
ATTR_YELLOW    = 0x32
ATTR_YELLOW_RI = 0x33
ATTR_TURQ_UL   = 0x34
ATTR_TURQ_ULRI = 0x35
ATTR_YELLOW_UL = 0x36
ATTR_NONDISP3  = 0x37
ATTR_PINK      = 0x38
ATTR_PINK_RI   = 0x39
ATTR_BLUE      = 0x3A
ATTR_BLUE_RI   = 0x3B
ATTR_PINK_UL   = 0x3C
ATTR_PINK_ULRI = 0x3D
ATTR_BLUE_UL   = 0x3E
ATTR_NONDISP4  = 0x3F

# All non-display attribute values (for reveal_hidden detection)
NONDISP_ATTRS = frozenset({ATTR_NONDISP, ATTR_NONDISP2, ATTR_NONDISP3, ATTR_NONDISP4})

# === AID values (terminal → host) ===
# Source: Wireshark packet-tn5250.c value_string aid_vals
# Inbound packet structure: [HDR(10)] [cursor_row:1] [cursor_col:1] [AID:1] [field-data...]
AID_TABLE: dict[str, int] = {
    "ENTER":  0xF1,   # NOTE: this is PF1 in 3270!
    "HELP":   0xF3,
    "ROLLDN": 0xF4,
    "ROLLUP": 0xF5,
    "PRINT":  0xF6,
    "RECBS":  0xF8,   # record backspace
    "CLEAR":  0xBD,
    "AUTO":   0x3F,   # SLP auto-enter
    "PA1":    0x6C,   # same as 3270
    "PA2":    0x6E,   # same as 3270
    "PA3":    0x6B,   # same as 3270
    # F1-F12: contiguous 0x31-0x3C
    "F1": 0x31, "F2": 0x32, "F3": 0x33, "F4": 0x34, "F5": 0x35, "F6": 0x36,
    "F7": 0x37, "F8": 0x38, "F9": 0x39, "F10": 0x3A, "F11": 0x3B, "F12": 0x3C,
    # F13-F24: contiguous 0xB1-0xBC
    "F13": 0xB1, "F14": 0xB2, "F15": 0xB3, "F16": 0xB4, "F17": 0xB5, "F18": 0xB6,
    "F19": 0xB7, "F20": 0xB8, "F21": 0xB9, "F22": 0xBA, "F23": 0xBB, "F24": 0xBC,
}

# Reverse lookup for AID-byte → name
AID_NAMES: dict[int, str] = {v: k for k, v in AID_TABLE.items()}

# === Telnet NEW-ENVIRON (RFC 2877) ===
# Used for IBMRSEED downgrade and DEVNAME spoofing
TELOPT_NEW_ENVIRON = 0x27
NE_IS    = 0x00
NE_SEND  = 0x01
NE_INFO  = 0x02
NE_VAR   = 0x00
NE_VALUE = 0x01
NE_ESC   = 0x02
NE_USERVAR = 0x03

# USERVAR names (ASCII, not EBCDIC — telnet layer)
USERVAR_IBMRSEED  = b"IBMRSEED"
USERVAR_DEVNAME   = b"DEVNAME"
USERVAR_IBMSUBSPW = b"IBMSUBSPW"   # the password (clear or encrypted)
USERVAR_USER      = b"USER"
# Phase 3 A2: initial-program/menu/library override (RFC 4777 §5)
USERVAR_IBMPROGRAM = b"IBMPROGRAM"
USERVAR_IBMIMENU   = b"IBMIMENU"
USERVAR_IBMCURLIB  = b"IBMCURLIB"
# Phase 3 A1: confirmation-record request (RFC 4777 §10.4)
USERVAR_IBMSENDCONFREC = b"IBMSENDCONFREC"

# Telnet IAC sequences
IAC = 0xFF
SB  = 0xFA
SE  = 0xF0
IAC_EOR = bytes([IAC, 0xEF])
