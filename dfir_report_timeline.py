#!/usr/bin/env python3
"""
DFIR Report Timeline Generator
==============================
Style: The DFIR Report - vertical timeline

Supports two input formats (auto-detected from extension):
  CSV  : timestamp, category, description, details
  XLSX : CrowdStrike IR Tracker (auto-mapped columns + ATT&CK normalisation)

Required dependencies:
    pip install pandas matplotlib openpyxl

Usage:
    python dfir_timeline.py -i events.csv   -o out.png -t "IR-2024-031"
    python dfir_timeline.py -i tracker.xlsx -o out.png -t "IR-2024-031"
    python dfir_timeline.py -i tracker.xlsx --preview
    python dfir_timeline.py -i events.csv   -o out.png --tlp AMBER \\
        --case-id "IR-2024-042" --author "CERT Acme" --contact "cert@acme.com"

CSV format (columns in any order, header required):
    timestamp,category,description,details[,host][,mitre_tactic]
    - timestamp : ISO-8601 or any format parseable by pandas.to_datetime
    - category  : free text or ATT&CK tactic name (normalised automatically)
    - host      : optional - prepended to details as "[host] details"
    - mitre_tactic : optional - used as category if category is empty

Architecture (9 sections):
    1  Input loaders      - CSV / CrowdStrike XLSX
    2  Visual constants   - colours, fonts
    3  Text helpers       - wrap, truncate, clean
    4  Layout constants   - dimensions in inches (matplotlib figure units)
    5  Height calculators - per-block height from text content
    6  Layout builder     - dual-column cursor algorithm
    7  Drawing primitives - rounded boxes, L-connectors
    8  Figure renderer    - matplotlib figure assembly
    9  CLI                - argparse entry point
"""

import argparse
import re
import sys
import textwrap
from datetime import datetime
from pathlib import Path

import pandas as pd
import matplotlib
# NOTE: matplotlib.use() MUST be called before any other matplotlib import.
# "Agg" is a non-interactive backend suitable for headless/server rendering.
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
from matplotlib.path import Path as MPath


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 1 - INPUT LOADERS
# ═════════════════════════════════════════════════════════════════════════════

_TECHNIQUE_TO_TACTIC = {
    # Partial ATT&CK coverage.
    # TO DO : Extend this dict.
    "T1078":"Initial Access",    "T1190":"Initial Access",
    "T1133":"Initial Access",    "T1566":"Initial Access",
    "T1059":"Execution",         "T1203":"Execution",
    "T1047":"Execution",         "T1053":"Execution",
    "T1204":"Execution",         "T1569":"Execution",
    "T1098":"Persistence",       "T1136":"Persistence",
    "T1543":"Persistence",       "T1546":"Persistence",
    "T1547":"Persistence",       "T1574":"Persistence",
    "T1548":"Privilege Escalation","T1068":"Privilege Escalation",
    "T1055":"Privilege Escalation","T1134":"Privilege Escalation",
    "T1027":"Defense Evasion",   "T1036":"Defense Evasion",
    "T1070":"Defense Evasion",   "T1562":"Defense Evasion",
    "T1003":"Credential Access", "T1110":"Credential Access",
    "T1552":"Credential Access", "T1558":"Credential Access",
    "T1016":"Discovery",         "T1018":"Discovery",
    "T1046":"Discovery",         "T1057":"Discovery",
    "T1069":"Discovery",         "T1082":"Discovery",
    "T1083":"Discovery",         "T1087":"Discovery",
    "T1135":"Discovery",
    "T1021":"Lateral Movement",  "T1534":"Lateral Movement",
    "T1550":"Lateral Movement",  "T1563":"Lateral Movement",
    "T1570":"Lateral Movement",
    "T1005":"Collection",        "T1074":"Collection",
    "T1114":"Collection",        "T1119":"Collection",
    "T1560":"Collection",
    "T1071":"Command & Control", "T1090":"Command & Control",
    "T1095":"Command & Control", "T1105":"Command & Control",
    "T1572":"Command & Control",
    "T1041":"Exfiltration",      "T1048":"Exfiltration",
    "T1567":"Exfiltration",
    "T1485":"Impact",            "T1486":"Impact",
    "T1489":"Impact",            "T1490":"Impact",
    "T1529":"Impact",            "T1561":"Impact",
}

_TACTIC_ALIASES = {
    "initial access":"Initial Access","execution":"Execution",
    "persistence":"Persistence","privilege escalation":"Privilege Escalation",
    "defense evasion":"Defense Evasion","credential access":"Credential Access",
    "discovery":"Discovery","lateral movement":"Lateral Movement",
    "collection":"Collection","command and control":"Command & Control",
    "command & control":"Command & Control","c2":"Command & Control",
    "exfiltration":"Exfiltration","impact":"Impact",
}

_SKIP = {"","nan","none","-","n/a","tbd"}


def _normalise_attack(raw) -> str:
    """
    Map a raw ATT&CK field to a canonical tactic label.

    Resolution order:
      1. Tactic alias match (e.g. "c2" => "Command & Control")
      2. Technique ID extraction (e.g. "T1059.001" => "Execution")
      3. Raw string truncated to 40 chars (fallback for unknown values)

    Returns "" for empty/null/placeholder values.
    """
    s = str(raw).strip()
    if s.lower() in _SKIP:
        return ""
    for alias, canonical in _TACTIC_ALIASES.items():
        if alias in s.lower():
            return canonical
    tactics = []
    for t in re.findall(r"T\d{4}(?:\.\d{3})?", s, re.IGNORECASE):
        tac = _TECHNIQUE_TO_TACTIC.get(t.split(".")[0].upper())
        if tac and tac not in tactics:
            tactics.append(tac)
    return ", ".join(tactics[:2]) if tactics else s[:40]


_CS_COL_TS     = "Date/Time (UTC)"
_CS_COL_ACT    = "Activity"
_CS_COL_DET    = "Details/Comments"
_CS_COL_ATTACK = "ATT&CK Alignment"
_CS_COL_SYSTEM = "System Name"
_CS_COL_STATUS = "Status/Tag"


def load_crowdstrike_xlsx(path, sheet="Timeline", filter_status=None):
    """
    Load a CrowdStrike IR Tracker workbook and return a normalised DataFrame.

    Parameters
    ----------
    path          : str | Path - path to the .xlsx file
    sheet         : str        - sheet name (default "Timeline")
    filter_status : str | None - if set, keep only rows whose Status/Tag column
                                 matches this value (case-insensitive)

    Returns
    -------
    pd.DataFrame with columns: timestamp, description, details, category
    Sorted ascending by timestamp.

    Raises
    ------
    ValueError if required columns (Date/Time, Activity) are missing.
    """
    df = pd.read_excel(path, sheet_name=sheet, header=1)
    df = df.loc[:, ~df.columns.str.startswith("Unnamed")]
    print(f"[xlsx] Sheet '{sheet}' - columns: {list(df.columns)}")
    for col in (_CS_COL_TS, _CS_COL_ACT):
        if col not in df.columns:
            raise ValueError(f"Column '{col}' not found. Found: {list(df.columns)}")
    df = df[df[_CS_COL_TS].notna()]
    df = df[df[_CS_COL_ACT].notna()]
    df = df[~df[_CS_COL_ACT].astype(str).str.strip().str.lower().isin(_SKIP)]
    df = df[~df[_CS_COL_ACT].astype(str).str.lower().str.startswith("example")]
    if filter_status and _CS_COL_STATUS in df.columns:
        df = df[df[_CS_COL_STATUS].astype(str).str.strip().str.lower()
                == filter_status.lower()]
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df[_CS_COL_TS], errors="coerce")
    df = df[df["timestamp"].notna()]
    if _CS_COL_DET in df.columns and _CS_COL_SYSTEM in df.columns:
        def _merge(row):
            sys = str(row.get(_CS_COL_SYSTEM,"")).strip()
            det = str(row.get(_CS_COL_DET,"")).strip()
            ok_s = sys.lower() not in _SKIP
            ok_d = det.lower() not in _SKIP
            if ok_s and ok_d: return f"[{sys}] {det}"
            if ok_d:          return det
            if ok_s:          return f"System: {sys}"
            return ""
        det_col = df.apply(_merge, axis=1)
    elif _CS_COL_DET in df.columns:
        det_col = df[_CS_COL_DET].fillna("").astype(str).str.strip()
    else:
        # Neither details nor system name column present.
        # BUG FIX: use pd.Series (not "") to avoid shape mismatch in DataFrame constructor.
        det_col = pd.Series([""] * len(df), index=df.index)
    out = pd.DataFrame({
        "timestamp":   df["timestamp"],
        "description": df[_CS_COL_ACT].astype(str).str.strip(),
        "details":     det_col,
        "category":    (df[_CS_COL_ATTACK].fillna("").apply(_normalise_attack)
                        if _CS_COL_ATTACK in df.columns else ""),
    })
    out = out.sort_values("timestamp").reset_index(drop=True)
    print(f"[xlsx] {len(out)} events loaded" if len(out) else "[xlsx] No events found.")
    return out


def load_csv(path):
    """
    Load a generic DFIR CSV file.

    Expected columns (header names are case-insensitive, whitespace-stripped):
      timestamp   : required - event datetime (any pandas-parseable format)
      description : optional - short event label
      details     : optional - verbose context shown in child box
      category    : optional - ATT&CK tactic or free text
      host        : optional - prepended to details as "[host] ..."
      mitre_tactic: optional - used as category when category is empty

    Internal columns "side" and "day" are dropped if present (legacy support).
    Rows with unparseable timestamps are silently dropped.
    """
    df = pd.read_csv(path)
    df.columns = df.columns.str.strip().str.lower()
    for col in ("side", "day"):
        if col in df.columns:
            df = df.drop(columns=[col])

    if "timestamp" not in df.columns:
        raise ValueError(f"CSV must have a 'timestamp' column. Found: {list(df.columns)}")

    # Ensure base columns exist
    for col, default in [("description", ""), ("details", ""), ("category", "")]:
        if col not in df.columns:
            df[col] = default

    # Use mitre_tactic as category if category is empty
    if "mitre_tactic" in df.columns:
        df["category"] = df.apply(
            lambda r: _normalise_attack(r["mitre_tactic"])
                      if clean(r.get("category", "")) == "" else r["category"],
            axis=1)

    # Merge host into details prefix (like CrowdStrike System Name)
    if "host" in df.columns:
        def _merge_host(row):
            host = clean(row.get("host", ""))
            det  = clean(row.get("details", ""))
            ok_h = host.lower() not in _SKIP
            ok_d = det.lower()  not in _SKIP
            if ok_h and ok_d:  return f"[{host}] {det}"
            if ok_d:           return det
            if ok_h:           return f"Host: {host}"
            return ""
        df["details"] = df.apply(_merge_host, axis=1)

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df[df["timestamp"].notna()].sort_values("timestamp").reset_index(drop=True)
    print(f"[csv]  {len(df)} events loaded" if len(df) else "[csv]  No events found.")
    return df


def load_input(path, sheet="Timeline", filter_status=None):
    """
    Dispatch to the correct loader based on file extension.

    Supported extensions: .csv, .xlsx, .xls
    Raises ValueError for any other extension.
    """
    suffix = Path(path).suffix.lower()
    if suffix in (".xlsx",".xls"):
        return load_crowdstrike_xlsx(path, sheet=sheet, filter_status=filter_status)
    elif suffix == ".csv":
        return load_csv(path)
    else:
        raise ValueError(f"Unsupported format '{suffix}'. Use .csv or .xlsx")


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 2 - VISUAL CONSTANTS
# All colour values are CSS hex strings.
# TLP palette follows the official TLP 2.0 specification (FIRST.org).
# Fonts: DejaVu Sans ships with matplotlib - no extra install required.
# ═════════════════════════════════════════════════════════════════════════════

BG              = "white"
AXIS_COLOR      = "#1a1a1a"
AXIS_LW         = 1.6
HEADER_FILL     = "#c0272d"
HEADER_TEXT     = "white"
DAY_FILL        = "#111111"
DAY_TEXT        = "white"
DAY_DATE_COLOR  = "#888888"
PARENT_FILL     = "white"
PARENT_BORDER   = "#2c2c2c"
PARENT_BORDER_W = 0.9
CHILD_FILL      = "white"
CHILD_BORDER    = "#aaaaaa"
CHILD_BORDER_W  = 0.7
TEXT_TS         = "#111111"
TEXT_DESC       = "#111111"
TEXT_CAT        = "#666666"
TEXT_CHILD      = "#333333"
NODE_COLOR      = "#2c2c2c"
CONN_COLOR      = "#555555"
CONN_LW         = 0.85
FONT            = "DejaVu Sans"

CATEGORY_COLORS = {
    "initial access":       "#e74c3c",
    "execution":            "#e67e22",
    "persistence":          "#8e44ad",
    "privilege escalation": "#9b59b6",
    "defense evasion":      "#7f8c8d",
    "credential access":    "#c0392b",
    "discovery":            "#2471a3",
    "lateral movement":     "#d35400",
    "collection":           "#1e8449",
    "command & control":    "#148f77",
    "exfiltration":         "#922b21",
    "impact":               "#7b241c",
}

TLP_COLORS = {
    "CLEAR":        ("#000000","#ffffff","#ffffff"),
    "GREEN":        ("#000000","#33cc00","#33cc00"),
    "AMBER":        ("#000000","#ffa500","#ffa500"),
    "AMBER+STRICT": ("#000000","#ffa500","#ffa500"),
    "RED":          ("#000000","#cc0000","#cc0000"),
}

def cat_color(cat):
    """Return the accent hex colour for a given ATT&CK tactic string.
    Falls back to neutral grey (#888888) for unknown / empty categories.
    Matching is case-insensitive substring - e.g. "Command & Control" matches key "command & control".
    """
    cl = cat.lower()
    for k,v in CATEGORY_COLORS.items():
        if k in cl: return v
    return "#888888"


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 3 - TEXT HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def clean(t):
    """Coerce any value to str, strip whitespace, and normalise pandas "nan" to ""."""
    t = str(t).strip()
    return "" if t == "nan" else t

def wrap_text(t, w):
    """Wrap text to width w (chars). Returns "" for empty/null input."""
    t = clean(t)
    if not t:
        return ""
    return "\n".join(textwrap.wrap(t, width=w, break_long_words=True, break_on_hyphens=True))

def _truncate_lines(t, w, max_lines):
    """Wrap text and hard-cap at max_lines, adding '…' if truncated."""
    t = clean(t)
    if not t:
        return ""
    lines = textwrap.wrap(t, width=w, break_long_words=True, break_on_hyphens=True)
    if len(lines) <= max_lines:
        return "\n".join(lines)
    return "\n".join(lines[:max_lines - 1] + [lines[max_lines - 1].rstrip() + " …"])

def line_count(t, w):
    """Return the number of wrapped lines for text t at width w. Returns 0 for empty input."""
    t = clean(t)
    return max(len(textwrap.wrap(t, width=w, break_long_words=True, break_on_hyphens=True)), 1) if t else 0


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 4 - LAYOUT CONSTANTS
# All dimensions are in matplotlib figure inches (same unit as figsize).
# FIG_W = 8.8 in (set in build_timeline). The axis sits at x = FIG_W / 2 = 4.4.
# Left column  : [AXIS_X - AXIS_GAP - PARENT_W … AXIS_X - AXIS_GAP]
# Right column : [AXIS_X + AXIS_GAP … AXIS_X + AXIS_GAP + PARENT_W]
# Child boxes extend further outward from their parent column.
# ═════════════════════════════════════════════════════════════════════════════

PARENT_W        = 3.15
CHILD_W         = 2.75
STRIPE_W        = 0.065
TEXT_PAD_L      = 0.10
TEXT_PAD_T      = 0.09
PARENT_LINE_H   = 0.155
CHILD_LINE_H    = 0.140
PARENT_PAD_V    = 0.14
CHILD_PAD_V     = 0.11
PARENT_WRAP     = 28
CHILD_WRAP      = 30
MAX_CHILD_LINES = 8     # hard cap: truncate details beyond this many lines
AXIS_GAP        = 0.20
CHILD_GAP       = 0.18
HEADER_H        = 0.75
FOOTER_H        = 0.55      # height of the footer bar
FOOTER_PAD      = 1.00      # space below last event before footer
CORNER_R        = 0.13

# Minimum clearance between any two blocks on the SAME side
MIN_GAP_SAME    = 0.18
# Minimum clearance between blocks on OPPOSITE sides
# (they share the axis so only the axis midpoint must not overlap)
MIN_GAP_OPP     = 0.08
# Minimum gap after a day marker before the first event
GAP_AFTER_DAY   = 0.10


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 5 - HEIGHT CALCULATORS
# ═════════════════════════════════════════════════════════════════════════════

def _parent_h(ts_str, desc, cat):
    """
    Compute the height of a parent event box in figure inches.

    The box contains up to 3 lines of text (timestamp, description, category).
    The category line is omitted when it duplicates the description content.
    Minimum height is one line + vertical padding.
    """
    show_cat = (cat
                and cat.lower() not in desc.lower()
                and desc.lower() not in cat.lower())
    total = max(
        line_count(ts_str, PARENT_WRAP)
        + line_count(desc,  PARENT_WRAP)
        + (line_count(cat,  PARENT_WRAP) if show_cat else 0),
        1)
    return total * PARENT_LINE_H + PARENT_PAD_V

def _child_h(det):
    """
    Compute the height of a child (details) box in figure inches.
    Returns 0 if det is empty - no child box is drawn in that case.
    Text is hard-capped at MAX_CHILD_LINES lines.
    """
    t = clean(det)
    if not t:
        return 0
    n = min(line_count(t, CHILD_WRAP), MAX_CHILD_LINES)
    return n * CHILD_LINE_H + CHILD_PAD_V

def _block_h(ph, ch):
    """Total vertical footprint of a parent + optional child block."""
    return ph + (CHILD_GAP + ch if ch > 0 else 0)


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 6 - LAYOUT BUILDER  (dual-column cursor)
# ═════════════════════════════════════════════════════════════════════════════

def _prepare(df):
    """
    Normalise a loaded events DataFrame for layout processing.

    Adds internal columns:
      _ts   : tz-naive datetime (pandas Timestamp)
      _date : date only (datetime.date)
      _day  : 1-based day number, relative to the earliest event date
      _time : "HH:MM UTC" string for display

    Drops legacy "side" and "day" columns if present.
    Ensures description, details, category columns exist (empty string default).
    Returns a copy sorted by _ts ascending.
    """
    df = df.copy()
    # Normalise column names - pandas columns are always str but strip whitespace
    df.columns = df.columns.str.strip().str.lower()
    for col in ("side","day"):
        if col in df.columns: df = df.drop(columns=[col])
    for col,dflt in [("category",""),("description",""),("details","")]:
        if col not in df.columns: df[col] = dflt
    df["_ts"]   = pd.to_datetime(df["timestamp"])
    df["_date"] = df["_ts"].dt.date
    dates       = sorted(df["_date"].unique())
    ref_date    = dates[0]
    # Real day number = calendar offset from first event date + 1
    df["_day"]  = df["_date"].map({d: (d - ref_date).days + 1 for d in dates})
    df["_time"] = df["_ts"].dt.strftime("%H:%M UTC")
    return df.sort_values("_ts").reset_index(drop=True)


def build_layout(df):
    """
    True dual-column packing.

    Each side tracks TWO independent cursors:
      *_parent_bot : bottom of the PARENT BOX only  => governs axis-dot clearance
      *_block_bot  : bottom of the full BLOCK (parent+child) => governs same-side clearance

    Placement rules for a new event on side S:
      A) same-side  : p_top ≤ S_block_bot  - MIN_GAP_SAME
                      (full previous block on same side must be cleared)
      B) axis-cross : p_mid_y ≤ opp_parent_bot - MIN_GAP_OPP
                      (dot on axis must not overlap the opposite parent box)
      C) day marker : p_top ≤ axis_bot - MIN_GAP_OPP

    Rule B is the key change: the child box of the OPPOSITE side does NOT
    block the next event - only the parent box (where the dot lives) does.
    This lets child boxes overlap vertically with the opposite column.
    """
    items        = []
    current_date = None
    side_toggle  = 0
    first_of_day = False
    prev_day_num = None
    last_side    = "right"   # track the actual last side used

    # Per-side bottom cursors (y, negative = downward)
    L_block_bot  = -HEADER_H
    R_block_bot  = -HEADER_H
    L_parent_bot = -HEADER_H
    R_parent_bot = -HEADER_H
    axis_bot     = -HEADER_H

    for _, row in df.iterrows():
        date   = row["_date"]
        ts_str = row["_time"]
        cat    = clean(row.get("category",""))
        desc   = clean(row.get("description",""))
        det    = clean(row.get("details",""))
        day_n  = row["_day"]

        # ── Day marker ────────────────────────────────────────────────────────
        if date != current_date:
            # The pill sits on the central axis - it only conflicts with
            # PARENT boxes (where the axis dots live), NOT with child boxes
            # (which are offset left/right into their columns).
            # So we can raise the pill up to just below the last parent boxes.
            floor = min(L_parent_bot, R_parent_bot, axis_bot) - 0.12
            bh       = 0.34
            pill_cy  = floor - bh / 2 - 0.08
            label_bot = pill_cy - bh / 2 - 0.16

            delta = day_n - prev_day_num if prev_day_num is not None else None

            items.append({
                "type": "day", "day_num": day_n,
                "date": date,  "mid_y":   pill_cy,
                "delta": delta,   # days since previous marker (None for first)
            })

            # Reset cursors to just below the date label.
            # Use a single tight gap - the first event's MIN_GAP_SAME will
            # NOT be added on top; we override it via axis_bot so only
            # GAP_AFTER_DAY separates the label from the first parent box.
            reset = label_bot - GAP_AFTER_DAY
            L_block_bot = R_block_bot = reset
            # Set parent cursors slightly above so constraint B doesn't push
            # the first event down unnecessarily
            L_parent_bot = R_parent_bot = reset
            axis_bot = reset
            current_date = date
            # Start new day from the side OPPOSITE to the last event placed
            side_toggle  = 0 if prev_day_num is None else (1 if last_side == "right" else 0)
            first_of_day = True
            prev_day_num = day_n

        # ── Side assignment ───────────────────────────────────────────────────
        side = "right" if side_toggle % 2 == 0 else "left"
        side_toggle += 1
        last_side = side

        ph = _parent_h(ts_str, desc, cat)
        ch = _child_h(det)

        # ── Constraint A : clear same-side full block ─────────────────────────
        # First event after a day marker uses GAP_AFTER_DAY (already baked
        # into the reset cursors), not the larger MIN_GAP_SAME
        gap_same    = 0.0 if first_of_day else MIN_GAP_SAME
        same_block  = L_block_bot  if side == "left" else R_block_bot
        p_top_A     = same_block - gap_same

        # ── Constraint B : dot must clear opposite PARENT box ─────────────────
        # dot is at p_mid_y = p_top - ph/2
        # we need p_mid_y ≥ opp_parent_bot + MIN_GAP_OPP  (remember: more negative = lower)
        # => p_top - ph/2 ≤ opp_parent_bot - MIN_GAP_OPP
        # => p_top ≤ opp_parent_bot - MIN_GAP_OPP + ph/2
        opp_parent  = R_parent_bot if side == "left" else L_parent_bot
        p_top_B     = opp_parent - MIN_GAP_OPP + ph / 2

        # ── Constraint C : clear day marker / axis label ──────────────────────
        p_top_C     = axis_bot - MIN_GAP_OPP

        # Topmost valid position (min = most upward constraint wins)
        p_top   = min(p_top_A, p_top_B, p_top_C)
        p_bot   = p_top - ph
        p_mid_y = (p_top + p_bot) / 2
        c_top   = p_bot - CHILD_GAP if ch else p_bot
        c_bot   = c_top - ch        if ch else p_bot

        items.append({
            "type":"event","side":side,
            "ts_str":ts_str,"cat":cat,"desc":desc,"det":det,
            "has_child":ch > 0,
            "p_top":p_top,"p_bot":p_bot,"p_h":ph,
            "c_top":c_top,"c_bot":c_bot,"c_h":ch,
            "p_mid_y":p_mid_y,
        })

        # Update cursors for this side
        if side == "left":
            L_parent_bot = p_bot
            L_block_bot  = c_bot
        else:
            R_parent_bot = p_bot
            R_block_bot  = c_bot

        first_of_day = False

    # Compute the true lowest y across all items (parent or child box bottom)
    lowest = min(L_block_bot, R_block_bot)
    total_h = abs(lowest) + FOOTER_H + 0.60
    return items, total_h


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 7 - DRAWING PRIMITIVES
# ═════════════════════════════════════════════════════════════════════════════

def rounded_box(ax, x, y_top, w, h, facecolor=PARENT_FILL,
                edgecolor=PARENT_BORDER, lw=PARENT_BORDER_W,
                radius=0.07, zorder=3):
    """
    Draw a rounded rectangle using FancyBboxPatch.

    Parameters
    ----------
    ax       : matplotlib Axes
    x, y_top : top-left corner (note: y_top is the TOP edge, positive = up)
    w, h     : width and height in figure inches
    radius   : corner rounding radius (figure inches)
    """
    ax.add_patch(FancyBboxPatch(
        (x, y_top - h), w, h,
        boxstyle=f"round,pad=0,rounding_size={radius}",
        facecolor=facecolor, edgecolor=edgecolor,
        linewidth=lw, zorder=zorder, clip_on=False,
    ))


def draw_L_connector(ax, px, py_bot, side, child_x, child_y_top, child_h):
    """
    Sharp-angle L: vertical DOWN first, then horizontal outward to child mid-height.
    left  => down then RIGHT  to child right edge (inner side)
    right => down then LEFT   to child left  edge (inner side)
    """
    c_mid_y = child_y_top - child_h / 2
    r = CORNER_R

    if side == "left":
        inner_x = child_x + CHILD_W
        ax.plot([px, px], [py_bot, c_mid_y + r],
                color=CONN_COLOR, lw=CONN_LW, zorder=2, solid_capstyle="butt")
        ax.add_patch(mpatches.PathPatch(
            MPath([(px, c_mid_y+r),(px, c_mid_y),(px-r, c_mid_y)],
                  [MPath.MOVETO, MPath.CURVE3, MPath.CURVE3]),
            facecolor="none", edgecolor=CONN_COLOR, lw=CONN_LW, zorder=2))
        ax.plot([px-r, inner_x],[c_mid_y, c_mid_y],
                color=CONN_COLOR, lw=CONN_LW, zorder=2, solid_capstyle="round")
    else:
        inner_x = child_x
        ax.plot([px, px], [py_bot, c_mid_y + r],
                color=CONN_COLOR, lw=CONN_LW, zorder=2, solid_capstyle="butt")
        ax.add_patch(mpatches.PathPatch(
            MPath([(px, c_mid_y+r),(px, c_mid_y),(px+r, c_mid_y)],
                  [MPath.MOVETO, MPath.CURVE3, MPath.CURVE3]),
            facecolor="none", edgecolor=CONN_COLOR, lw=CONN_LW, zorder=2))
        ax.plot([px+r, inner_x],[c_mid_y, c_mid_y],
                color=CONN_COLOR, lw=CONN_LW, zorder=2, solid_capstyle="round")


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 8 - FIGURE RENDERER
# ═════════════════════════════════════════════════════════════════════════════

def build_timeline(df, title, output,
                   tlp="CLEAR", case_id="", logo_path="",
                   author="", version="", contact=""):
    """
    Render the full timeline figure and save it to disk.

    Parameters
    ----------
    df        : pd.DataFrame from load_input() - must contain timestamp, description,
                details, category columns (all others ignored)
    title     : str  - headline shown in the red header band
    output    : str  - output file path (.png recommended, DPI=200)
    tlp       : str  - TLP classification: CLEAR / GREEN / AMBER / AMBER+STRICT / RED
    case_id   : str  - case reference shown in header + footer
    logo_path : str  - optional path to a PNG/JPEG logo (placed in header, left side)
    author    : str  - author name shown in footer (left)
    version   : str  - report version shown in footer (centre)
    contact   : str  - contact email/url shown in footer below author
    """

    df              = _prepare(df)
    items, total_h  = build_layout(df)

    FIG_W  = 8.8
    AXIS_X = FIG_W / 2

    fig, ax = plt.subplots(figsize=(FIG_W, total_h), facecolor=BG)
    ax.set_facecolor(BG)
    ax.set_xlim(0, FIG_W)
    ax.set_ylim(-total_h, 0)
    ax.axis("off")

    # Axis spine
    # Axis spine - runs from header down to the top of the footer bar
    ft       = -total_h + 0.08
    foot_top = ft + FOOTER_H
    ax.plot([AXIS_X, AXIS_X], [foot_top, -HEADER_H],
            color=AXIS_COLOR, lw=AXIS_LW, zorder=1, solid_capstyle="butt")

    # ── Header ────────────────────────────────────────────────────────────────
    rounded_box(ax, 0.28, 0, FIG_W-0.56, HEADER_H,
                facecolor=HEADER_FILL, edgecolor="none", lw=0, radius=0.12, zorder=4)

    if logo_path:
        try:
            from matplotlib.image import imread as mpl_imread
            img  = mpl_imread(logo_path)
            lh   = HEADER_H * 0.62
            lw_d = lh * img.shape[1] / img.shape[0]
            lx   = 0.55
            ly   = -HEADER_H/2 - lh/2
            ax.imshow(img, extent=[lx, lx+lw_d, ly, ly+lh],
                      aspect="auto", zorder=6, clip_on=False)
        except (FileNotFoundError, OSError, ValueError) as exc:
            # Logo is optional - log the reason and continue without it.
            print(f"[warn] Could not load logo '{logo_path}': {exc}")

    ax.text(AXIS_X, -HEADER_H/2, title,
            fontsize=12, fontweight="bold", color=HEADER_TEXT,
            ha="center", va="center", fontfamily=FONT, zorder=5)

    if case_id:
        ax.text(AXIS_X, -HEADER_H*0.82, f"Case: {case_id}",
                fontsize=7.5, color="#ffcccc",
                ha="center", va="center", fontfamily=FONT, zorder=5)

    tlp_key = tlp.upper()
    tlp_fill, tlp_txt, tlp_border = TLP_COLORS.get(tlp_key, TLP_COLORS["CLEAR"])
    tbw, tbh = 1.05, 0.28
    tx = FIG_W - 0.28 - tbw - 0.15
    rounded_box(ax, tx, -HEADER_H/2+tbh/2, tbw, tbh,
                facecolor=tlp_fill, edgecolor=tlp_border, lw=1.0, radius=0.06, zorder=6)
    ax.text(tx+tbw/2, -HEADER_H/2, f"TLP:{tlp_key}",
            fontsize=7.2, fontweight="bold", color=tlp_txt,
            ha="center", va="center", fontfamily=FONT, zorder=7)

    # ── Events & day markers ──────────────────────────────────────────────────
    for item in items:

        if item["type"] == "day":
            my, bw, bh = item["mid_y"], 0.88, 0.34
            rounded_box(ax, AXIS_X-bw/2, my+bh/2, bw, bh,
                        facecolor=DAY_FILL, edgecolor="none", lw=0,
                        radius=0.09, zorder=4)
            ax.text(AXIS_X, my+0.04, f"Day {item['day_num']}",
                    fontsize=8.5, fontweight="bold", color=DAY_TEXT,
                    ha="center", va="center", fontfamily=FONT, zorder=5)

            # Date below pill
            ax.text(AXIS_X, my-bh/2-0.05,
                    item["date"].strftime("%Y-%m-%d"),
                    fontsize=6.5, color=DAY_DATE_COLOR,
                    ha="center", va="top", fontfamily=FONT, zorder=5)

            # Delta badge: "+Nd" between this and previous day marker
            if item["delta"] is not None:
                delta_str = f"+{item['delta']}d"
                dbw = 0.52
                dbh = 0.20
                dx  = AXIS_X + bw/2 + 0.08
                dy  = my
                rounded_box(ax, dx, dy+dbh/2, dbw, dbh,
                            facecolor="#e8e8e8", edgecolor="#aaaaaa",
                            lw=0.5, radius=0.04, zorder=5)
                ax.text(dx + dbw/2, dy, delta_str,
                        fontsize=6.2, color="#555555", fontweight="bold",
                        ha="center", va="center", fontfamily=FONT, zorder=6)
            continue

        side    = item["side"]
        p_top   = item["p_top"]
        p_bot   = item["p_bot"]
        p_h     = item["p_h"]
        p_mid_y = item["p_mid_y"]

        # Horizontal connector + axis dot
        if side == "left":
            p_x = AXIS_X - AXIS_GAP - PARENT_W
            ax.plot([AXIS_X, p_x+PARENT_W], [p_mid_y, p_mid_y],
                    color=CONN_COLOR, lw=CONN_LW, zorder=2)
        else:
            p_x = AXIS_X + AXIS_GAP
            ax.plot([AXIS_X, p_x], [p_mid_y, p_mid_y],
                    color=CONN_COLOR, lw=CONN_LW, zorder=2)

        ax.plot(AXIS_X, p_mid_y, "o", color=NODE_COLOR, markersize=5.5, zorder=3)

        # Parent box
        accent = cat_color(item["cat"])
        rounded_box(ax, p_x, p_top, PARENT_W, p_h,
                    facecolor=PARENT_FILL, edgecolor=PARENT_BORDER,
                    lw=PARENT_BORDER_W, radius=0.07, zorder=3)
        rounded_box(ax, p_x, p_top, STRIPE_W, p_h,
                    facecolor=accent, edgecolor="none", lw=0, radius=0.05, zorder=4)

        tx2 = p_x + STRIPE_W + TEXT_PAD_L
        ty  = p_top - TEXT_PAD_T

        ax.text(tx2, ty, item["ts_str"],
                fontsize=7.8, fontweight="bold", color=TEXT_TS,
                ha="left", va="top", fontfamily=FONT, zorder=5)
        ty -= PARENT_LINE_H * line_count(item["ts_str"], PARENT_WRAP)

        if item["desc"]:
            ax.text(tx2, ty, wrap_text(item["desc"], PARENT_WRAP),
                    fontsize=7.6, color=TEXT_DESC,
                    ha="left", va="top", fontfamily=FONT, zorder=5, linespacing=1.3)
            ty -= PARENT_LINE_H * line_count(item["desc"], PARENT_WRAP)

        def _norm(s):
            return s.lower().replace("-","").replace(";","").replace(",","").split()
        show_cat = (item["cat"]
                    and set(_norm(item["cat"])) != set(_norm(item["desc"]))
                    and not all(w in _norm(item["desc"]) for w in _norm(item["cat"])))
        if show_cat:
            ax.text(tx2, ty, wrap_text(item["cat"], PARENT_WRAP),
                    fontsize=7.0, color=TEXT_CAT, style="italic",
                    ha="left", va="top", fontfamily=FONT, zorder=5, linespacing=1.3)

        # Child box
        if item["has_child"]:
            c_top = item["c_top"]
            c_h   = item["c_h"]

            if side == "left":
                conn_ax = p_x + PARENT_W * (1/3)
                child_x = conn_ax - CHILD_W - 0.20
            else:
                conn_ax = p_x + PARENT_W * (2/3)
                child_x = conn_ax + 0.20

            draw_L_connector(ax, px=conn_ax, py_bot=p_bot,
                             side=side, child_x=child_x,
                             child_y_top=c_top, child_h=c_h)

            rounded_box(ax, child_x, c_top, CHILD_W, c_h,
                        facecolor=CHILD_FILL, edgecolor=CHILD_BORDER,
                        lw=CHILD_BORDER_W, radius=0.06, zorder=3)

            ax.text(child_x+0.12, c_top-CHILD_PAD_V/2,
                    _truncate_lines(item["det"], CHILD_WRAP, MAX_CHILD_LINES),
                    fontsize=7.2, color=TEXT_CHILD,
                    ha="left", va="top", fontfamily=FONT, linespacing=1.35, zorder=5)

    # ── Footer ────────────────────────────────────────────────────────────────
    rounded_box(ax, 0.28, ft+FOOTER_H, FIG_W-0.56, FOOTER_H,
                facecolor="#f0f0f0", edgecolor="#cccccc", lw=0.5, radius=0.10, zorder=2)

    fy = ft + FOOTER_H * 0.65
    if author:
        ax.text(0.55, fy, author, fontsize=8.0, fontweight="bold", color="#111111",
                ha="left", va="top", fontfamily=FONT, zorder=5)
    if contact:
        ax.text(0.55, fy-0.20, contact, fontsize=7.0, color="#555555",
                ha="left", va="top", fontfamily=FONT, zorder=5)

    center_parts = []
    if version:      center_parts.append(f"v{version}")
    center_parts.append(f"Generated: {datetime.now().strftime('%Y-%m-%d')}")
    ax.text(AXIS_X, fy, "  |  ".join(center_parts),
            fontsize=7.2, color="#444444",
            ha="center", va="top", fontfamily=FONT, zorder=5)

    if case_id:
        ax.text(FIG_W-0.55, fy, f"Ref: {case_id}",
                fontsize=7.5, fontweight="bold", color="#333333",
                ha="right", va="top", fontfamily=FONT, zorder=5)

    plt.savefig(output, dpi=200, bbox_inches="tight",
                facecolor=BG, edgecolor="none")
    plt.close(fig)
    n    = sum(1 for i in items if i["type"] == "event")
    days = len({i["day_num"] for i in items if i["type"] == "day"})
    print(f"[✓] Saved => {output}  ({n} events, {days} day(s))")


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 9 - CLI
# ═════════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="DFIR Timeline - CSV or CrowdStrike IR Tracker (.xlsx)")
    ap.add_argument("--input",    "-i", required=True)
    ap.add_argument("--output",   "-o", default="timeline.png")
    ap.add_argument("--title",    "-t", default="Incident Timeline")
    ap.add_argument("--sheet",    "-s", default="Timeline")
    ap.add_argument("--status",         default=None)
    ap.add_argument("--tlp",            default="CLEAR",
                    choices=["CLEAR","GREEN","AMBER","AMBER+STRICT","RED"])
    ap.add_argument("--case-id",        default="")
    ap.add_argument("--logo",           default="")
    ap.add_argument("--author",         default="")
    ap.add_argument("--version",        default="")
    ap.add_argument("--contact",        default="")
    ap.add_argument("--preview",        action="store_true")
    args = ap.parse_args()

    df = load_input(args.input, sheet=args.sheet, filter_status=args.status)

    if args.preview:
        pd.set_option("display.max_colwidth", 55)
        pd.set_option("display.width", 180)
        print(df[["timestamp","category","description","details"]].to_string(index=False))
        print(f"\n{len(df)} events - preview only.")
        return

    if df.empty:
        sys.exit("[ERROR] No events to render.")

    title = args.title or (
        f"Incident Timeline  "
        f"{df['timestamp'].min().strftime('%Y-%m-%d')} => "
        f"{df['timestamp'].max().strftime('%Y-%m-%d')}"
    )

    build_timeline(df, title=title, output=args.output,
                   tlp=args.tlp, case_id=args.case_id, logo_path=args.logo,
                   author=args.author, version=args.version, contact=args.contact)

if __name__ == "__main__":
    main()
