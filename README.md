# DFIR Report Timeline Generator

Generate incident timelines in the style of [The DFIR Report](https://thedfirreport.com/) vertical layout, ATT&CK colour coding, TLP watermark, child detail boxes, from a plain CSV or a CrowdStrike IR Tracker XLSX.

---

## Features

- **Two input formats** - generic CSV *or* CrowdStrike IR Tracker XLSX (auto-detected from extension)
- **TLP watermark** - `CLEAR / GREEN / AMBER / AMBER+STRICT / RED` badge in the header per [TLP 2.0](https://www.first.org/tlp/)
- **Child detail boxes** - verbose context rendered in a secondary box connected by an L-connector
- **Logo support** - drop a PNG/JPEG into the header

---

## Requirements

```
Python 3.9+
pandas
matplotlib
openpyxl        # for .xlsx input
```

```bash
pip install pandas matplotlib openpyxl
```

---

## Quick start

```bash
# From a CSV
python dfir_timeline.py -i events.csv -o timeline.png -t "IR-2024-031"

# From a CrowdStrike IR Tracker
python dfir_timeline.py -i tracker.xlsx -o timeline.png -t "IR-2024-031"

# Full metadata
python dfir_timeline.py -i events.csv -o timeline.png \
    --tlp AMBER \
    --case-id "IR-2024-042" \
    --author "CERT Acme" \
    --contact "cert@acme.com" \
    --logo logo.png \
    --version "1.2"
```

---

## CSV format

Headers are **case-insensitive** and whitespace-stripped. Column order doesn't matter.

```csv
timestamp,description,details,category,host,mitre_tactic
2026-03-15 02:14:00,VPN auth from unusual IP,"Source: 185.220.101.x - 3 failed attempts then success",Initial Access,fw-edge-01,T1078
2026-03-15 02:31:00,PowerShell encoded command executed,"cmd: powershell -enc JABjAG...",Execution,WKSTN-047,T1059.001
2026-03-15 03:05:00,LSASS memory read via ProcDump,"C:\Windows\Temp\lsass.dmp written (39 MB)",Credential Access,WKSTN-047,T1003.001
2026-03-16 03:22:00,SMB lateral movement to DC,"Net use \\DC01\ADMIN$ - auth with harvested creds",Lateral Movement,WKSTN-047,T1021.002
2026-03-16 04:01:00,Cobalt Strike beacon C2 check-in,"HTTPS to 104.21.x.x:443 - 60s jitter",Command & Control,DC01,T1071.001
2026-03-17 04:47:00,Volume Shadow Copies deleted,"vssadmin delete shadows /all /quiet",Impact,DC01,T1490
2026-03-17 04:52:00,Ransomware deployment,"BLACKCAT dropped to C:\ProgramData - 847 files encrypted",Impact,DC01,T1486
```

| Column | Required | Description |
|---|---|---|
| `timestamp` | ✅ | ISO-8601 or any format `pandas.to_datetime` accepts |
| `description` | - | Short event label (parent box) |
| `details` | - | Verbose context (child box, max 8 lines) |
| `category` | - | ATT&CK tactic or free text - auto-normalised |
| `host` | - | Hostname - prepended to details as `[host] ...` |
| `mitre_tactic` | - | Used as category when `category` is empty |

---

## CLI reference

| Flag | Short | Default | Description |
|---|---|---|---|
| `--input` | `-i` | *required* | Path to `.csv` or `.xlsx` |
| `--output` | `-o` | `timeline.png` | Output PNG path |
| `--title` | `-t` | Auto (date range) | Headline text in the header |
| `--sheet` | `-s` | `Timeline` | XLSX sheet name |
| `--status` | | `None` | Filter XLSX rows by Status/Tag column |
| `--tlp` | | `CLEAR` | TLP classification badge |
| `--case-id` | | | Case reference shown in header + footer |
| `--author` | | | Author shown in footer |
| `--contact` | | | Contact email/URL shown in footer |
| `--logo` | | | Path to a PNG/JPEG logo for the header |
| `--version` | | | Report version shown in footer |
| `--preview` | | `false` | Dump events to stdout, skip rendering |

---

## CrowdStrike IR Tracker (XLSX)

Point `--input` at a CrowdStrike-style IR Tracker workbook. The loader expects:

- Sheet name: `Timeline` (override with `--sheet`)
- Header on **row 2** (row 1 is typically the tracker title)
- Columns: `Date/Time (UTC)`, `Activity`, `Details/Comments`, `ATT&CK Alignment`, `System Name`, `Status/Tag`

Unknown or extra columns are silently ignored. Rows with placeholder values (`-`, `n/a`, `tbd`, `example ...`) are automatically filtered out.

Filter by status tag (e.g. keep only confirmed events):

```bash
python dfir_timeline.py -i tracker.xlsx --status "Confirmed" -o confirmed.png
```

---

## Vibe coding disclosure

This tool was built iteratively with Claude Sonnet
