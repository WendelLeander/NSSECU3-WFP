# ⚡ USB RegParse — Windows USB Registry Forensic Parser
### v2.0.0 | Inspired by USB Detective | Built with Python

A Python-based forensic tool that mines the Windows Registry for a complete
history of every USB device ever connected to a machine — with full support
for both **live registry scanning** and **offline hive file parsing**.

---

## What's New in v2.0

| Change | Details |
|---|---|
| **Renamed** | Tool is now called **USB RegParse** (was USB Detective) |
| **Offline hive parsing** | Load raw SYSTEM / SOFTWARE / NTUSER.DAT hive files from disk — no running Windows required |
| **EMDMgmt volume info** | Extracts the user-assigned **Volume Name / Label** and **Volume Serial Number** from the ReadyBoost residue key |
| **MountedDevices binary decode** | Fully decodes MBR disk signature + partition offset and GPT DMIO GUID from raw binary values |
| **User attribution** | Ties MountPoints2 volume GUIDs back to specific Windows user accounts, proving *who* used the drive |
| **First Connected timestamp** | Read from device Properties DEVPKEY subkeys (`0064`) |
| **Last Disconnected timestamp** | Read from device Properties DEVPKEY subkeys (`0067`) |
| **Auto-detect username** | Browsing for NTUSER.DAT automatically extracts the username from the file path |

---

## Features

| Feature | Details |
|---|---|
| **Live scan** | Reads directly from the running Windows registry |
| **Offline scan** | Parses exported hive files — ideal for forensic disk images and dead-box analysis |
| **USBSTOR parsing** | Extracts all USB mass-storage devices (flash drives, external HDDs, SSDs) |
| **USB enum parsing** | Covers non-storage devices (keyboards, cameras, hubs, phones, etc.) |
| **Volume Name / Label** | User-assigned partition label recovered from EMDMgmt |
| **Volume Serial Number** | Filesystem serial (the 8-char hex shown by `vol` / `dir`) |
| **Drive letter mapping** | Correlates MBR disk signatures and GPT volume GUIDs to drive letters |
| **User attribution** | Shows which Windows account(s) accessed each volume via MountPoints2 |
| **First / Last Connected** | DEVPKEY timestamp subkeys, with SetupAPI log and LastWrite fallbacks |
| **Last Disconnected** | DEVPKEY timestamp subkeys (`0067`) |
| **SetupAPI log mining** | First-install timestamp fallback from `setupapi.dev.log` (live mode) |
| **Vendor lookup** | Resolves VID numbers to brand names (SanDisk, Kingston, WD, etc.) |
| **Search & filter** | Real-time search + class / vendor dropdown filters |
| **Sortable columns** | Click any column header to sort ascending / descending |
| **Detail pane** | Expanded view with all fields for the selected device |
| **Detail popup** | Double-click any row for a full-screen record view |
| **Export** | CSV, JSON, or plain-text report |
| **Clipboard copy** | Copy individual fields (name, serial, GUID, key path) or all fields at once |
| **Dark GUI** | Professional forensics-style dark theme |

---

## Registry Sources

```
HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
    └─ USB mass storage devices, vendor/product/serial, ParentIdPrefix

HKLM\SYSTEM\CurrentControlSet\Enum\USB
    └─ All USB devices including HID, cameras, hubs, phones

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt
    └─ Volume Name (user label) and Volume Serial Number

HKLM\SYSTEM\MountedDevices
    └─ Binary-decoded MBR signatures, GPT GUIDs, drive letter assignments

HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{53f5630d-...}
    └─ Volume interface class — links USB serial numbers to volume GUIDs

HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
    └─ Per-user volume access history (user attribution)

HKLM\SYSTEM\...\Enum\USBSTOR\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}
    └─ DEVPKEY timestamps: 0064 = First Install, 0066 = Last Arrival, 0067 = Last Removal

C:\Windows\INF\setupapi.dev.log
    └─ First-install timestamps (live mode only)
```

---

## Requirements

- **Python 3.10+** (uses `X | Y` union type hints)
- **Windows only** — `winreg` is a Windows standard library module
- **`python-registry`** — required for offline hive parsing only

```bash
pip install python-registry
```

> Live scanning works with no extra packages. `python-registry` is only needed
> when you switch to **Offline / Hive Files** mode.

---

## Installation & Usage

```bash
# Run directly
python usb_regparse.py

# For full registry access (recommended for live scan):
# Right-click → "Run as Administrator"
# or from an elevated terminal:
python usb_regparse.py
```

> **Administrator privileges** are recommended for live scanning. Without
> elevation, some SYSTEM hive keys may return "Access denied" and certain
> DEVPKEY timestamp subkeys may be unreadable.

---

## Scan Modes

### 🔴 Live Registry Scan
Reads directly from the running Windows registry. Best for incident response
on a live machine. Press **F5** or click **Scan** to start.

### 💾 Offline / Hive Files Mode
Parses raw registry hive files exported from another machine or extracted from
a forensic disk image. This is the **forensically sound** approach — it never
touches the original evidence.

**Required hive files:**

| Hive | Path on source system | Required? |
|---|---|---|
| `SYSTEM` | `C:\Windows\System32\config\SYSTEM` | ✅ Yes |
| `SOFTWARE` | `C:\Windows\System32\config\SOFTWARE` | Recommended |
| `NTUSER.DAT` | `C:\Users\<username>\NTUSER.DAT` | Recommended |

**Steps:**
1. Select **Offline / Hive Files** in the mode selector
2. Browse for the `SYSTEM` hive (required)
3. Browse for `SOFTWARE` hive (for EMDMgmt volume info)
4. Browse for one or more `NTUSER.DAT` files — the username is **auto-detected**
   from the file path (e.g. selecting `C:\Users\Downloads\NTUSER.DAT` fills
   `"Downloads"` automatically)
5. Click **Offline Scan**

---

## How It Works

```
1.  SetupAPI log parsed (live mode) → first-install timestamp cache
2.  USBSTOR hive walked → vendor/product/serial/ParentIdPrefix/timestamps
3.  USB enum hive walked → VID/PID/friendly name/timestamps
4.  EMDMgmt parsed → volume name + volume serial number
5.  MountedDevices decoded → MBR signatures, GPT GUIDs, drive letters
6.  DeviceClasses walked → serial number → volume GUID mapping
7.  MountPoints2 parsed (per user) → user attribution + drive letter correlation
8.  Enrichment pass → all data cross-referenced into each device record
9.  Deduplication → (serial, VID, PID, name) key
10. Results displayed in GUI
```

### Timestamp Priority Chain

| Priority | Source | Field |
|---|---|---|
| 1st | DEVPKEY `0064` (Properties subkey) | First Connected |
| 1st | DEVPKEY `0066` (Properties subkey) | Last Connected |
| 1st | DEVPKEY `0067` (Properties subkey) | Last Disconnected |
| 2nd | `setupapi.dev.log` (live only) | First Connected fallback |
| 3rd | Registry key LastWrite time | Last Connected fallback |

### User Attribution Chain

```
MountPoints2 {GUID}
    → GUID match in MountedDevices          → drive letter
    → \??\Volume{GUID} binary equality      → drive letter
    → MountedDevices entry scan by GUID     → drive letter
```

---

## Table Columns

| Column | Source |
|---|---|
| Friendly Name | `FriendlyName` / `DeviceDesc` registry value |
| Volume Name | EMDMgmt key — user-assigned partition label |
| Vendor | Resolved from VID database or `Ven_` field |
| VID / PID | USB enum hive (`VID_xxxx&PID_yyyy`) |
| Serial Number | USBSTOR instance key name |
| Vol Serial | EMDMgmt `VolumeSerialNumber` (8-char hex) |
| Drive | MountedDevices correlation |
| First Connected | DEVPKEY `0064` / SetupAPI log |
| Last Connected | DEVPKEY `0066` / key LastWrite |
| Last Disconnected | DEVPKEY `0067` |
| Users | MountPoints2 → MountedDevices correlation |
| Class | `Mass Storage` or `USB Device` |

### Row Colour Coding

| Colour | Meaning |
|---|---|
| 🟢 Green text | Mass storage device (from USBSTOR hive) |
| 🔵 Cyan text | USB device with confirmed user attribution |
| White text | Other USB device (HID, hub, camera, etc.) |

---

## Keyboard Shortcuts

| Key | Action |
|---|---|
| `F5` | Run scan |
| `Ctrl+E` | Export results |
| `Escape` | Clear search / filter |
| Double-click row | Full detail popup |

---

## Export Formats

All exports include every field: Volume Name, Volume Serial, Disk Signature,
Volume GUID, ParentIdPrefix, all three timestamps, Users, and registry key path.

| Format | Best for |
|---|---|
| `.csv` | Excel / spreadsheet analysis |
| `.json` | Scripted post-processing or SIEM ingestion |
| `.txt` | Human-readable narrative report |

---

## Vendor Database

The built-in VID database covers ~40 common manufacturers including SanDisk,
Kingston, Seagate, Western Digital, Samsung, Apple, Sony, Logitech, Microsoft,
HP, Canon, Epson, Huawei, and more. Unknown VIDs are displayed as
`Unknown (VID XXXX)`.

---

## Forensic Notes

- The tool is **read-only** — it never writes, modifies, or deletes any
  registry data or hive file content.
- **Offline mode is forensically sound**: operates on copies of hive files
  and never touches the original evidence media.
- **EMDMgmt** persists even after a USB drive is reformatted or renamed,
  making it a reliable artefact for historical volume labels.
- **MountPoints2** is user-specific — its presence proves that a particular
  Windows account interacted with a volume, not just that the computer
  recorded the hardware.
- **DEVPKEY timestamps** (`Properties\{83da6326...}`) are the most accurate
  source for connection/disconnection times and survive device re-installs
  better than SetupAPI log entries.
- **ParentIdPrefix** links USBSTOR records to MountedDevices binary values
  and is a key artefact in USB forensics timelines.

---

## Disclaimer

This tool is intended for **digital forensics, IT auditing, and security
research** purposes only. Always ensure you have proper authorisation before
examining registry data. The authors assume no liability for misuse.