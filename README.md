# ⚡ USB RegParse — Windows USB Registry Forensic Parser
### v2.1.0 | Inspired by USB Detective | Built with Python

A Python-based forensic tool that mines the Windows Registry for a complete
history of every USB device ever connected to a machine — with full support
for both **live registry scanning** and **offline hive file parsing**.

---

## What's New in v2.1

| Change | Details |
|---|---|
| **SeBackupPrivilege** | Properly enables the backup privilege via correctly-typed ctypes argtypes/restype, fixing silent 64-bit handle truncation that caused all DEVPKEY timestamp reads to fail |
| **REG_OPTION_BACKUP_RESTORE** | Registry keys protected by SYSTEM-only ACLs (USBSTOR Properties timestamps) are now opened with the backup flag, bypassing the ACL check for Administrators |
| **Admin privilege warning** | A pop-up warns at scan time if the script is not running as Administrator, listing exactly which fields will be blank and how to fix it |
| **Offline `RegistryValue` fix** | python-registry returns a `RegistryValue` object, not raw bytes — the offline value wrapper now calls `.raw_data()` as a fallback to always return pure bytes to the FILETIME parser |
| **Exhaustive value name probing** | `_get_ts_from_prop` now tries `"Data"`, `"(default)"`, and `""` in order, covering all known Windows schema variants |
| **Dirty hive detection** | Warns when `SYSTEM.LOG1` / `SYSTEM.LOG2` are found alongside a loaded hive, explains the "dirty hive" phenomenon, and directs users to `rla.exe` |
| **DEVPKEY subkey navigation fix** | Replaced non-existent `find_subkey()` call (python-registry API) with the correct `subkey()` method, fixing all offline timestamp parsing |
| **WPD volume labels** | `SOFTWARE\Microsoft\Windows Portable Devices\Devices` parsed for user-assigned volume labels |
| **VolumeInfoCache** | `SOFTWARE\Microsoft\Windows Search\VolumeInfoCache` parsed for drive-letter-indexed volume labels |
| **MountedDevices UTF-16 decode** | Detects and decodes the UTF-16-LE device path format used by most removable flash drives (`_??_USBSTOR#...`), enabling ParentIdPrefix-based drive letter matching |

---

## Features

| Feature | Details |
|---|---|
| **Live scan** | Reads directly from the running Windows registry via `winreg` + `SeBackupPrivilege` |
| **Offline scan** | Parses raw hive files via `python-registry` — ideal for forensic disk images and dead-box analysis |
| **USBSTOR parsing** | Extracts all USB mass-storage devices (flash drives, external HDDs, SSDs) |
| **USB enum parsing** | Covers non-storage devices (keyboards, cameras, hubs, phones, etc.) |
| **Volume Name / Label** | User-assigned partition label from WPD → VolumeInfoCache → EMDMgmt (priority order) |
| **Volume Serial Number** | Filesystem serial (8-char hex shown by `vol` / `dir`) from EMDMgmt |
| **Drive letter mapping** | MBR disk signature, GPT volume GUID, and UTF-16 ParentIdPrefix correlation via MountedDevices |
| **User attribution** | Shows which Windows account(s) accessed each volume via MountPoints2 GUID correlation |
| **First Connected** | DEVPKEY `0064` binary blob → FILETIME, with SetupAPI log fallback |
| **Last Connected** | DEVPKEY `0066` binary blob → FILETIME, with registry LastWrite fallback |
| **Last Disconnected** | DEVPKEY `0067` binary blob → FILETIME |
| **Admin warning** | Pop-up at scan time when not running as Administrator |
| **Dirty hive detection** | Warns when transaction logs are present alongside the offline SYSTEM hive |
| **SetupAPI log mining** | First-install timestamp fallback from `setupapi.dev.log` (live mode only) |
| **Vendor lookup** | Resolves VID numbers to brand names (SanDisk, Kingston, WD, etc.) |
| **Search & filter** | Real-time search + class / vendor dropdown filters |
| **Sortable columns** | Click any column header to sort ascending / descending |
| **Detail pane** | Expanded view with all fields for the selected device |
| **Detail popup** | Double-click any row for a full-screen record view |
| **Export** | CSV, JSON, or plain-text report |
| **Clipboard copy** | Copy individual fields or all fields at once |
| **Dark GUI** | Professional forensics-style dark theme |

---

## Requirements

- **Python 3.10+** (uses `X | Y` union type hints and `match` expressions)
- **Windows only** — `winreg` and `ctypes.windll` are Windows-specific
- **`python-registry`** — required for offline hive parsing

```bash
pip install python-registry
```

> Live scanning works without `python-registry`. It is only required when
> using **Offline / Hive Files** mode.

---

## Installation & Usage

```bash
# Run directly (limited — timestamps may be blank)
python usb_regparse.py

# Recommended — run as Administrator for complete timestamp data
# Option 1: Right-click the script → "Run as Administrator"
# Option 2: From an elevated command prompt or terminal:
python usb_regparse.py

# Option 3: Via psexec as NT AUTHORITY\SYSTEM (maximum access)
psexec -i -s python usb_regparse.py
```

---

## Administrator Privileges

> **This is the most important operational note for this tool.**

The `Properties` subkeys under `USBSTOR` (which hold the DEVPKEY timestamps
for First Connected, Last Connected, and Last Disconnected) are protected by
a Windows ACL that grants **READ only to `NT AUTHORITY\SYSTEM`**.

Even running as Administrator, the live Windows registry API returns
`ERROR_ACCESS_DENIED` for these keys by default.

USB RegParse resolves this using two mechanisms:

1. **`SeBackupPrivilege`** — Administrators possess this privilege but it is
   disabled by default. USB RegParse enables it via `AdjustTokenPrivileges`
   with properly typed ctypes argtypes (fixing the silent 64-bit handle
   truncation present in naive implementations).

2. **`REG_OPTION_BACKUP_RESTORE` (0x4)** — Passed as the `ulOptions` argument
   to `winreg.OpenKey()` when a `PermissionError` occurs. This flag tells the
   kernel to bypass the ACL check and use the backup privilege instead.

**If you run without Administrator privileges**, the tool will:
- Display a warning pop-up listing exactly which fields will be blank
- Still collect vendor names, serial numbers, drive letters, and volume info
- Show `Unknown` for First Connected, Last Connected, and Last Disconnected

| Run level | Timestamps | All other fields |
|---|---|---|
| Standard user | ❌ Blank | ✅ Available |
| Administrator | ✅ Full | ✅ Available |
| `psexec -s` (SYSTEM) | ✅ Full | ✅ Available |

---

## Scan Modes

### 🔴 Live Registry Scan

Reads directly from the running Windows registry. Best for incident response
on a live machine. Requires Administrator for complete timestamp data.
Press **F5** or click **Scan** to start.

### 💾 Offline / Hive Files Mode

Parses raw registry hive files exported from another machine or extracted
from a forensic disk image. No Administrator required — python-registry
reads file bytes directly, bypassing all Windows registry ACLs.

**Required hive files:**

| Hive | Path on source system | Purpose |
|---|---|---|
| `SYSTEM` | `C:\Windows\System32\config\SYSTEM` | ✅ Required — device records + timestamps |
| `SOFTWARE` | `C:\Windows\System32\config\SOFTWARE` | Recommended — volume names, WPD labels |
| `NTUSER.DAT` | `C:\Users\<username>\NTUSER.DAT` | Recommended — user attribution |

**Steps:**
1. Select **Offline / Hive Files** in the mode selector
2. Browse for the `SYSTEM` hive (required)
3. Browse for `SOFTWARE` hive (for volume labels and EMDMgmt data)
4. Browse for one or more `NTUSER.DAT` files — the **username is auto-detected**
   from the file path (e.g. `C:\Users\Downloads\NTUSER.DAT` fills `"Downloads"`)
5. Click **Offline Scan**

---

## The Dirty Hive Problem

> **Critical for offline analysis of hives copied from a live system.**

Modern Windows does **not** flush registry changes immediately to the hive
file on disk. Instead it writes to transaction logs:

```
C:\Windows\System32\config\SYSTEM.LOG1
C:\Windows\System32\config\SYSTEM.LOG2
```

If you extracted the `SYSTEM` hive from a running machine with a tool like
FTK Imager, the base `SYSTEM` file is **dirty** — recent DEVPKEY timestamps
for recently connected USB devices may only exist in `SYSTEM.LOG1`, not in
the base file. `python-registry` does not replay transaction logs.

**USB RegParse detects dirty hives** by checking for `.LOG1` / `.LOG2` files
in the same folder as the selected hive. If found, it shows a warning dialog
explaining the issue and offering to cancel so you can clean the hive first.

**To produce a clean hive before scanning:**

```bash
# 1. Copy SYSTEM, SYSTEM.LOG1, and SYSTEM.LOG2 into one folder
# 2. Run Eric Zimmerman's Registry Log Applicator:
rla.exe -d C:\Path\To\HiveFolder

# 3. Load the output SYSTEM file into USB RegParse
```

`rla.exe` is free and available at: https://ericzimmerman.github.io

| Scenario | Result |
|---|---|
| Hive exported from a powered-off machine (disk image) | Clean — no logs needed |
| Hive copied with FTK Imager from live machine | Likely dirty — run `rla.exe` first |
| Hive loaded from VSS snapshot | Usually clean |

---

## DEVPKEY Timestamp Technical Details

The DEVPKEY timestamps are stored as **binary blobs**, not as registry string
values. The full path to each blob is:

```
HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\<device>\<instance>\
    Properties\{83da6326-97a6-4088-9453-a1923f573b29}\
        00000064\00000000  →  value "Data"   (First Connected)
        00000066\00000000  →  value "Data"   (Last Connected)
        00000067\00000000  →  value "Data"   (Last Disconnected)
```

Each `Data` value is a **12-byte structure**:

```
Bytes 0–3  : DEVPROPTYPE tag  →  0x10 0x00 0x00 0x00  (VT_FILETIME)
Bytes 4–11 : FILETIME         →  100-nanosecond intervals since 1601-01-01 UTC
```

The parser detects the `0x10` header and skips it before decoding the
8-byte FILETIME — a fix for the common mistake of reading from offset 0
which produces astronomically large corrupt timestamps (year 200,000+).

**Windows version schema differences:**

| Version | Property subkey name | Value name |
|---|---|---|
| Windows 10 / 11 | `00000064` (8-digit) | `Data` (named value) |
| Windows 8 / older | `0064` (4-digit) | `(default)` (unnamed) |

USB RegParse probes both schemas for every device.

---

## Registry Sources

```
HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
    └─ Mass storage devices: vendor, product, serial, ParentIdPrefix

HKLM\SYSTEM\CurrentControlSet\Enum\USB
    └─ All USB devices: VID, PID, friendly name, service driver

HKLM\SYSTEM\...\Enum\USBSTOR\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}
    └─ DEVPKEY timestamps: 0064 First Connected, 0066 Last Connected, 0067 Last Disconnected

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt
    └─ Volume serial numbers and hardware-name-based volume descriptions

HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices
    └─ User-assigned volume labels (most accurate label source, serial-indexed)

HKLM\SOFTWARE\Microsoft\Windows Search\VolumeInfoCache
    └─ Volume labels indexed by drive letter (what Windows Explorer shows)

HKLM\SYSTEM\MountedDevices
    └─ Three binary formats: MBR disk sig, GPT DMIO GUID, UTF-16 device path
       All decoded and cross-referenced to assign drive letters

HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{53f5630d-...}
    └─ Volume interface class — maps USB serial numbers to volume GUIDs

HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
    └─ Per-user volume GUIDs — proves which user accounts accessed each drive

C:\Windows\INF\setupapi.dev.log
    └─ First-install timestamps for devices (live mode only, fallback)
```

---

## How It Works

```
1.  SetupAPI log parsed (live only)         → first-install timestamp cache
2.  USBSTOR hive walked                     → vendor/product/serial/ParentIdPrefix
3.  DEVPKEY Properties subkeys read         → First Connected / Last Disconnected
4.  USB enum hive walked                    → VID/PID/friendly name
5.  EMDMgmt parsed                          → volume serial + hardware description
6.  Windows Portable Devices parsed         → user-assigned volume labels
7.  VolumeInfoCache parsed                  → drive-letter → label mapping
8.  MountedDevices decoded (3 formats)      → MBR sig, GUID, UTF-16 device path
9.  MountPoints2 parsed (all users)         → volume GUID → username attribution
10. DeviceClasses walked                    → serial → volume GUID mapping
11. Enrichment pass                         → all sources cross-referenced per device
12. Deduplication                           → (serial, VID, PID, name) key
13. GUI populated
```

### Timestamp Priority Chain

| Priority | Source | Field populated |
|---|---|---|
| 1st | DEVPKEY `00000064` / `0064` binary blob | First Connected |
| 1st | DEVPKEY `00000066` / `0066` binary blob | Last Connected |
| 1st | DEVPKEY `00000067` / `0067` binary blob | Last Disconnected |
| 2nd | `setupapi.dev.log` (live only) | First Connected fallback |
| 3rd | USBSTOR instance key LastWrite time | Last Connected fallback |

### Volume Label Priority Chain

| Priority | Source | Notes |
|---|---|---|
| 1st | Windows Portable Devices (`FriendlyName`) | User-assigned label, serial-indexed |
| 2nd | VolumeInfoCache (`VolumeLabel`) | Drive-letter-indexed, exact Explorer label |
| 3rd | EMDMgmt key name | Hardware description, persists after reformats |

### Drive Letter Resolution Chain

```
1. Volume GUID match via DeviceClasses + MountedDevices
2. MBR disk signature match via MountedDevices
3. UTF-16 device path / ParentIdPrefix match via MountedDevices
4. USB serial number direct match via MountedDevices
```

---

## Table Columns

| Column | Source |
|---|---|
| Friendly Name | `FriendlyName` / `DeviceDesc` registry value |
| Volume Name | WPD → VolumeInfoCache → EMDMgmt (priority order) |
| Vendor | Resolved from VID database or `Ven_` field in USBSTOR |
| VID / PID | USB enum hive (`VID_xxxx&PID_yyyy`) |
| Serial Number | USBSTOR instance key name (strip `&0` suffix) |
| Vol Serial | EMDMgmt `VolumeSerialNumber` (8-char hex) |
| Drive | MountedDevices binary correlation |
| First Connected | DEVPKEY `0064` / SetupAPI log |
| Last Connected | DEVPKEY `0066` / instance key LastWrite |
| Last Disconnected | DEVPKEY `0067` |
| Users | MountPoints2 GUID → MountedDevices correlation |
| Class | `Mass Storage` (USBSTOR) or `USB Device` (USB enum) |

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

All three formats include every parsed field: Friendly Name, Volume Name,
Volume Serial, Vendor, VID/PID, Serial Number, Drive Letter, Disk Signature,
Volume GUID, ParentIdPrefix, First Connected, Last Connected, Last Disconnected,
Users, Device Class, and Registry Key path.

| Format | Best for |
|---|---|
| `.csv` | Excel / spreadsheet analysis, timeline pivoting |
| `.json` | Scripted post-processing, SIEM ingestion, automation |
| `.txt` | Human-readable narrative report, court exhibits |

---

## Vendor Database

The built-in VID database covers ~40 common manufacturers including SanDisk,
Kingston, Seagate, Western Digital, Samsung, Apple, Sony, Logitech, Microsoft,
HP, Canon, Epson, Huawei, and more. Unknown VIDs display as `Unknown (VID XXXX)`.

---

## Forensic Notes

- The tool is **read-only** — it never writes, modifies, or deletes registry
  data or hive file content.
- **Offline mode is forensically sound** — operates on copies of hive files
  and never touches original evidence media.
- **The `Properties` ACL** (`SYSTEM`-only read) is bypassed in live mode via
  `SeBackupPrivilege` + `REG_OPTION_BACKUP_RESTORE`. This requires the process
  to be running as Administrator. The privilege enablement uses properly typed
  `argtypes`/`restype` in ctypes to prevent silent 64-bit handle truncation.
- **EMDMgmt** persists even after a USB drive is reformatted or renamed,
  making it a reliable artefact for historical volume labels.
- **MountPoints2** is user-specific — its presence proves that a particular
  Windows account interacted with a volume, not just that the computer saw
  the hardware.
- **ParentIdPrefix** is stored in the USBSTOR instance key and also encoded
  in the UTF-16-LE binary values in MountedDevices — the primary correlation
  method for drive letter assignment on removable flash drives.
- **Dirty hives** are a critical consideration when working with hives copied
  from live systems. Always use `rla.exe` to replay transaction logs before
  loading a hive into any offline parsing tool.

---

## Disclaimer

This tool is intended for **digital forensics, IT auditing, and security
research** purposes only. Always ensure you have proper authorisation before
examining registry data. The authors assume no liability for misuse.