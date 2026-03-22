r"""
╔══════════════════════════════════════════════════════════════════╗
║                USB RegParse  v2.0.0                             ║
║          Windows USB Registry Forensic Parser                   ║
║  Inspired by USB Detective — built for digital forensics         ║
╚══════════════════════════════════════════════════════════════════╝

WHAT'S NEW IN v2.0:
  - Offline Hive Parsing via python-registry (pip install python-registry)
  - EMDMgmt key parsed for Volume Name & Volume Serial Number
  - MountedDevices binary decoded (MBR disk-sig + partition offset,
    GPT DMIO GUID) and correlated with USBSTOR ParentIdPrefix
  - User Attribution: MountPoints2 GUIDs tied to MountedDevices
    entries, proving which Windows user accessed each drive
  - First Connected timestamp from device Properties DEVPKEY subkeys
  - Last Disconnected timestamp from device Properties DEVPKEY subkeys
  - Renamed from "USB Detective" to "USB RegParse"

Registry hives examined:
  HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR        - mass-storage
  HKLM\SYSTEM\CurrentControlSet\Enum\USB             - all USB
  HKLM\SOFTWARE\Microsoft\Windows NT\...\EMDMgmt     - volume info
  HKLM\SYSTEM\MountedDevices                         - drive letters
  HKCU\SOFTWARE\...\Explorer\MountPoints2            - user volumes
  HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{...} - correlation
  C:\Windows\INF\setupapi.dev.log                    - first-install times

Device Properties DEVPKEY timestamps (under each instance key):
  Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0064  First Install
  Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0066  Last Arrival
  Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0067  Last Removal
"""

# ── Standard Library ────────────────────────────────────────────────────────
import os
import sys
import re
import csv
import json
import struct
import threading
import traceback
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dataclasses import dataclass, field

# winreg is Windows-only; we check the platform before use
if sys.platform == "win32":
    import winreg
else:
    winreg = None  # type: ignore  (handled at runtime)

# ── Optional: python-registry for offline hive parsing ─────────────────────
# Install with: pip install python-registry
try:
    from Registry.Registry import Registry as _OfflineHive
    OFFLINE_AVAILABLE = True
except ImportError:
    _OfflineHive = None
    OFFLINE_AVAILABLE = False


# ════════════════════════════════════════════════════════════════════════════
#  APP CONSTANTS & COLOUR PALETTE
# ════════════════════════════════════════════════════════════════════════════

APP_TITLE   = "USB RegParse"
APP_VER     = "2.0.0"
APP_SUBHEAD = "Windows USB Registry Forensic Parser"

# Dark forensics colour scheme
CLR_BG       = "#0d1117"
CLR_SURFACE  = "#161b22"
CLR_SURFACE2 = "#1c2128"
CLR_BORDER   = "#30363d"
CLR_ACCENT   = "#00e5ff"   # electric cyan
CLR_ACCENT2  = "#7ee787"   # soft green – mass-storage rows
CLR_ACCENT3  = "#a371f7"   # purple – offline-mode highlights
CLR_WARN     = "#f0883e"   # amber
CLR_DANGER   = "#ff4444"   # red
CLR_TEXT     = "#e6edf3"
CLR_MUTED    = "#8b949e"
CLR_SELECT   = "#1f6feb"

FONT_MONO  = ("Consolas", 10)
FONT_BODY  = ("Segoe UI", 10)
FONT_HEAD  = ("Segoe UI Semibold", 10)
FONT_TITLE = ("Segoe UI", 20, "bold")
FONT_SMALL = ("Segoe UI", 9)

# Registry path constants
REG_USBSTOR    = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
REG_USB        = r"SYSTEM\CurrentControlSet\Enum\USB"
REG_EMDMGMT    = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt"
REG_MOUNTED    = r"SYSTEM\MountedDevices"
REG_MNTPNT     = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
REG_DEVCLASSES = r"SYSTEM\CurrentControlSet\Control\DeviceClasses"

# Device Properties GUID for timestamps (DEVPKEY_Device_InstallDate family)
PROP_GUID           = "{83da6326-97a6-4088-9453-a1923f573b29}"
PROP_FIRST_INSTALL  = "0064"   # First Install Date   (FILETIME REG_BINARY)
PROP_LAST_INSTALL   = "0065"   # Last  Install Date
PROP_LAST_ARRIVAL   = "0066"   # Last  Arrival  = Last Connected
PROP_LAST_REMOVAL   = "0067"   # Last  Removal  = Last Disconnected

# Volume device interface class GUID (used to correlate disk → volume)
GUID_VOLUME_IFACE   = "{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"
GUID_DISK_IFACE     = "{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"

# SetupAPI first-install log
SETUPAPI_DEV_LOG = Path(os.environ.get("SystemRoot", r"C:\Windows"),
                        "INF", "setupapi.dev.log")

# Windows FILETIME epoch
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


# ════════════════════════════════════════════════════════════════════════════
#  VENDOR DATABASE
# ════════════════════════════════════════════════════════════════════════════

VENDOR_DB: dict[str, str] = {
    "0781": "SanDisk",           "0951": "Kingston Technology",
    "058F": "Alcor Micro",       "13FE": "Kingston (Phison)",
    "8644": "Intenso",           "0BC2": "Seagate",
    "059B": "Iomega",            "1058": "Western Digital",
    "04E8": "Samsung",           "0461": "Primax / Generic",
    "05AC": "Apple",             "0403": "FTDI",
    "04A9": "Canon",             "04B8": "Epson",
    "03F0": "HP",                "04F9": "Brother",
    "046D": "Logitech",          "045E": "Microsoft",
    "0CF3": "Qualcomm Atheros",  "8087": "Intel (Hub)",
    "0BDA": "Realtek",           "2109": "VIA Labs (Hub)",
    "1A40": "Terminus Tech",     "0424": "Microchip / SMSC",
    "0B95": "ASIX Electronics",  "067B": "Prolific Tech",
    "2357": "TP-Link",           "0E8D": "MediaTek",
    "18D1": "Google",            "2A70": "OnePlus",
    "1D6B": "Linux Foundation",  "0525": "Netchip Technology",
    "0557": "ATEN International","04DA": "Panasonic",
    "054C": "Sony",              "0BDB": "Ericsson",
    "12D1": "Huawei",            "2A45": "Meizu",
    "05C8": "Cheng Uei (Foxlink)","0471": "Philips",
}


def resolve_vendor(vid: str) -> str:
    return VENDOR_DB.get(vid.upper(), f"Unknown (VID {vid})")


def parse_vid_pid(device_id: str) -> tuple[str, str]:
    vid = re.search(r"VID_([0-9A-Fa-f]{4})", device_id)
    pid = re.search(r"PID_([0-9A-Fa-f]{4})", device_id)
    return (vid.group(1).upper() if vid else "Unknown",
            pid.group(1).upper() if pid else "Unknown")


# ════════════════════════════════════════════════════════════════════════════
#  REGISTRY ABSTRACTION LAYER
#  HiveKey: unified wrapper for winreg handles AND python-registry keys.
#  RegistryContext: exposes open_lm / open_cu for both live and offline modes.
# ════════════════════════════════════════════════════════════════════════════

class HiveKey:
    """
    Thin wrapper that presents a single consistent API over two
    very different backends:

      Live   backend → winreg handle  (int on Windows)
      Offline backend → python-registry RegistryKey object

    All parsing code uses HiveKey exclusively so it never needs to
    know which backend is active.
    """

    __slots__ = ("_h", "_live", "_name_str")

    def __init__(self, handle, live: bool, key_name: str = ""):
        self._h         = handle     # winreg handle OR python-registry RegistryKey
        self._live      = live
        self._name_str  = key_name   # only meaningful for live keys (winreg doesn't expose name)

    # ── Identity ─────────────────────────────────────────────────────────────

    @property
    def name(self) -> str:
        if self._live:
            return self._name_str
        try:
            return self._h.name()
        except Exception:
            return self._name_str

    # ── Navigation ────────────────────────────────────────────────────────────

    def subkeys(self) -> list["HiveKey"]:
        """Enumerate all direct child keys."""
        if self._live:
            result, idx = [], 0
            while True:
                try:
                    n = winreg.EnumKey(self._h, idx)
                    h = winreg.OpenKey(self._h, n)
                    result.append(HiveKey(h, True, n))
                    idx += 1
                except OSError:
                    break
            return result
        else:
            return [HiveKey(sk, False) for sk in self._h.subkeys()]

    def open(self, path: str) -> "HiveKey":
        """
        Open a descendant key by backslash-separated path.
        Raises OSError if any component is missing.
        """
        if self._live:
            h = winreg.OpenKey(self._h, path)
            return HiveKey(h, True, path.split("\\")[-1])
        else:
            # python-registry: navigate one component at a time
            parts = path.split("\\")
            k = self._h
            for part in parts:
                k = k.find_subkey(part)
                if k is None:
                    raise OSError(f"Subkey not found: {part!r}")
            return HiveKey(k, False)

    def try_open(self, path: str) -> "HiveKey | None":
        """Open a descendant key; return None instead of raising."""
        try:
            return self.open(path)
        except Exception:
            return None

    # ── Values ────────────────────────────────────────────────────────────────

    def value(self, name: str, default=None):
        """Read a single value by name.  Returns raw data or default."""
        if self._live:
            try:
                data, _ = winreg.QueryValueEx(self._h, name)
                return data
            except OSError:
                return default
        else:
            try:
                return self._h.value(name).value()
            except Exception:
                return default

    def values(self) -> list[tuple[str, object]]:
        """Return all (name, data) pairs for this key."""
        if self._live:
            result, idx = [], 0
            while True:
                try:
                    n, d, _ = winreg.EnumValue(self._h, idx)
                    result.append((n, d))
                    idx += 1
                except OSError:
                    break
            return result
        else:
            try:
                return [(v.name(), v.value()) for v in self._h.values()]
            except Exception:
                return []

    # ── Timestamp ─────────────────────────────────────────────────────────────

    def last_write_str(self) -> str:
        """
        Return the key's last-write timestamp as a UTC string.
        For USBSTOR instance keys this is the last time the device was seen.
        """
        if self._live:
            try:
                info = winreg.QueryInfoKey(self._h)
                dt = _filetime_to_dt(info[2])
                return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "Unknown"
            except OSError:
                return "Unknown"
        else:
            try:
                ts = self._h.timestamp()
                if ts:
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    return ts.strftime("%Y-%m-%d %H:%M:%S UTC")
            except Exception:
                pass
            return "Unknown"

    # ── Resource management ───────────────────────────────────────────────────

    def close(self):
        if self._live and self._h is not None:
            try:
                winreg.CloseKey(self._h)
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class RegistryContext:
    """
    Provides open_lm() / open_cu() / get_all_users_cu() for both scan modes.

    Live mode  → delegates to winreg (HKEY_LOCAL_MACHINE / HKEY_CURRENT_USER)
    Offline mode → delegates to python-registry hive objects loaded from disk

    Path convention for open_lm():
      Paths MUST include the hive-root prefix, e.g.
        "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR"
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt"
      In offline mode, "CurrentControlSet" is automatically replaced with
      the active control set number read from the SYSTEM\\Select key.
    """

    def __init__(self, live: bool = True,
                 system_path:   str | None = None,
                 software_path: str | None = None,
                 ntuser_paths:  list[tuple[str, str]] | None = None):
        """
        live          – True for live registry scan, False for offline hive files.
        system_path   – Path to SYSTEM hive file  (offline mode).
        software_path – Path to SOFTWARE hive file (offline mode).
        ntuser_paths  – List of (hive_file_path, username) tuples (offline mode).
        """
        self.live = live
        self._control_set = "ControlSet001"  # fallback
        self._sys:     object | None = None  # python-registry Registry object
        self._soft:    object | None = None
        self._ntusers: list[tuple[object, str]] = []  # (Registry, username)

        if not live:
            if not OFFLINE_AVAILABLE:
                raise RuntimeError(
                    "python-registry is required for offline mode.\n"
                    "Install it with: pip install python-registry")

            # Load SYSTEM hive and detect active control set
            if system_path:
                try:
                    self._sys = _OfflineHive(system_path)
                    try:
                        sel = self._sys.open("Select")
                        cur = sel.value("Current").value()
                        self._control_set = f"ControlSet{cur:03d}"
                    except Exception:
                        pass
                except Exception as exc:
                    raise RuntimeError(
                        f"Cannot open SYSTEM hive: {system_path}\n{exc}") from exc

            if software_path:
                try:
                    self._soft = _OfflineHive(software_path)
                except Exception as exc:
                    raise RuntimeError(
                        f"Cannot open SOFTWARE hive: {software_path}\n{exc}") from exc

            for hive_path, username in (ntuser_paths or []):
                try:
                    self._ntusers.append((_OfflineHive(hive_path), username))
                except Exception:
                    pass  # Invalid NTUSER.DAT – skip silently

    # ── HKLM opener ──────────────────────────────────────────────────────────

    def open_lm(self, path: str) -> HiveKey:
        """
        Open a HKLM path.  Path must start with 'SYSTEM\\' or 'SOFTWARE\\'.
        Returns a HiveKey wrapping the result.
        Raises OSError / RuntimeError on failure.
        """
        if self.live:
            h = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
            return HiveKey(h, True, path.split("\\")[-1])

        # ── Offline routing ──────────────────────────────────────────────
        # Replace the placeholder so callers can use consistent path strings
        path = path.replace("CurrentControlSet", self._control_set, 1)
        upper = path.upper()

        if upper.startswith("SYSTEM\\"):
            if not self._sys:
                raise RuntimeError("SYSTEM hive not loaded")
            stripped = path[len("SYSTEM\\"):]
            return HiveKey(self._sys.open(stripped), False)

        if upper.startswith("SOFTWARE\\"):
            if not self._soft:
                raise RuntimeError("SOFTWARE hive not loaded")
            stripped = path[len("SOFTWARE\\"):]
            return HiveKey(self._soft.open(stripped), False)

        raise OSError(f"Unknown hive prefix for path: {path!r}")

    def try_open_lm(self, path: str) -> HiveKey | None:
        try:
            return self.open_lm(path)
        except Exception:
            return None

    # ── HKCU opener ──────────────────────────────────────────────────────────

    def open_cu(self, path: str) -> HiveKey:
        """Open a HKCU path (current user in live mode, first NTUSER.DAT in offline)."""
        if self.live:
            h = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path)
            return HiveKey(h, True, path.split("\\")[-1])

        if not self._ntusers:
            raise RuntimeError("No NTUSER.DAT loaded")
        reg, _ = self._ntusers[0]
        return HiveKey(reg.open(path), False)

    def get_all_users_cu(self, path: str) -> list[tuple[HiveKey, str]]:
        """
        Open a HKCU path across ALL users.
        Live mode   → current user only.
        Offline mode → all loaded NTUSER.DAT files.
        Returns list of (HiveKey, username) pairs.
        """
        if self.live:
            try:
                h = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path)
                user = os.environ.get("USERNAME", "Current User")
                return [(HiveKey(h, True, path.split("\\")[-1]), user)]
            except OSError:
                return []

        result = []
        for reg, username in self._ntusers:
            try:
                result.append((HiveKey(reg.open(path), False), username))
            except Exception:
                pass
        return result

    def get_current_username(self) -> str:
        if self.live:
            return os.environ.get("USERNAME", "Current User")
        if self._ntusers:
            return ", ".join(u for _, u in self._ntusers)
        return "Unknown"


# ════════════════════════════════════════════════════════════════════════════
#  DATA MODEL
# ════════════════════════════════════════════════════════════════════════════

class USBDevice:
    """
    Represents one USB device as reconstructed from all registry sources.
    Fields are populated incrementally by the various parsing stages.
    """

    __slots__ = (
        # Core identity
        "device_class", "vendor_id", "product_id", "vendor_name",
        "friendly_name", "serial_number", "disk_id", "rev",
        "raw_key", "service", "hardware_ids",
        # Volume information (from EMDMgmt)
        "volume_name", "volume_serial",
        # Timestamps
        "first_connected",    # DEVPKEY 0064  or SetupAPI log
        "last_connected",     # DEVPKEY 0066  or key LastWrite
        "last_disconnected",  # DEVPKEY 0067
        # Drive / mount correlation (from MountedDevices)
        "drive_letter", "disk_signature", "volume_guid",
        # Disk-level identifier (from USBSTOR instance key)
        "parent_id_prefix",
        # User attribution (from MountPoints2 correlation)
        "user_accounts",
    )

    def __init__(self):
        for s in self.__slots__:
            setattr(self, s, "")

    def as_dict(self) -> dict:
        return {s: getattr(self, s) for s in self.__slots__}

    def as_row(self) -> tuple:
        """Values in the same order as COLUMNS defined in the GUI."""
        return (
            self.friendly_name    or "Unknown Device",
            self.volume_name      or "—",
            self.vendor_name      or "—",
            self.vendor_id        or "—",
            self.product_id       or "—",
            self.serial_number    or "N/A",
            self.volume_serial    or "—",
            self.drive_letter     or "—",
            self.first_connected  or "Unknown",
            self.last_connected   or "Unknown",
            self.last_disconnected or "Unknown",
            self.user_accounts    or "—",
            self.device_class     or "—",
        )


# ════════════════════════════════════════════════════════════════════════════
#  UTILITY / TIMESTAMP HELPERS
# ════════════════════════════════════════════════════════════════════════════

def _filetime_to_dt(ft: int) -> datetime | None:
    """Convert a Windows FILETIME (100-ns intervals since 1601-01-01) to datetime."""
    if not ft or ft <= 0:
        return None
    try:
        return FILETIME_EPOCH + timedelta(microseconds=ft // 10)
    except (OverflowError, OSError, ValueError):
        return None


def _filetime_bytes_to_str(data: bytes) -> str:
    """
    Parse an 8-byte little-endian FILETIME (REG_BINARY) and return a
    formatted UTC timestamp string, or '' on failure.
    """
    if not isinstance(data, bytes) or len(data) < 8:
        return ""
    ft = struct.unpack_from("<Q", data, 0)[0]
    dt = _filetime_to_dt(ft)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else ""


def _read_devpkey_timestamps(inst_key: HiveKey) -> dict[str, str]:
    """
    Read the four DEVPKEY timestamp values stored under:
      <instance_key>\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}

    Returns a dict with keys:
      "first_connected"   ← value 0064
      "last_connected"    ← value 0066
      "last_disconnected" ← value 0067
    """
    result: dict[str, str] = {}
    prop_root = inst_key.try_open("Properties")
    if prop_root is None:
        return result
    guid_key = prop_root.try_open(PROP_GUID)
    if guid_key is None:
        prop_root.close()
        return result

    mapping = {
        PROP_FIRST_INSTALL: "first_connected",
        PROP_LAST_ARRIVAL:  "last_connected",
        PROP_LAST_REMOVAL:  "last_disconnected",
    }
    for val_id, field_name in mapping.items():
        raw = guid_key.value(val_id)
        if isinstance(raw, bytes):
            ts = _filetime_bytes_to_str(raw)
            if ts:
                result[field_name] = ts

    guid_key.close()
    prop_root.close()
    return result


# ════════════════════════════════════════════════════════════════════════════
#  SETUPAPI LOG PARSER
#  Provides first-install timestamps for devices before devpkey data exists.
# ════════════════════════════════════════════════════════════════════════════

def parse_setupapi_log() -> dict[str, str]:
    """
    Parse C:\\Windows\\INF\\setupapi.dev.log.

    The log records each new device installation:
      [Device Install (Hardware initiated) - USBSTOR\\Disk&...\\<serial>&0]
           Section start YYYY/MM/DD HH:MM:SS.mmm

    Returns { UPPERCASE_DEVICE_ID: "YYYY-MM-DD HH:MM:SS" }
    """
    timestamps: dict[str, str] = {}
    if not SETUPAPI_DEV_LOG.exists():
        return timestamps

    dev_pat  = re.compile(r"\[Device Install.*?-\s+(.*?)\]", re.IGNORECASE)
    time_pat = re.compile(r"Section start\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})",
                          re.IGNORECASE)
    current = None
    try:
        with SETUPAPI_DEV_LOG.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                m = dev_pat.search(line)
                if m:
                    current = m.group(1).strip().upper()
                    continue
                if current:
                    t = time_pat.search(line)
                    if t:
                        timestamps[current] = t.group(1).replace("/", "-")
                        current = None
    except (PermissionError, OSError):
        pass
    return timestamps


# ════════════════════════════════════════════════════════════════════════════
#  EMDMGMT PARSER  — Volume Name & Volume Serial Number
#
#  The EMDMgmt key (ReadyBoost residue) stores a subkey for every volume
#  Windows ever ReadyBoost-evaluated.  The subkey NAME encodes:
#    <DeviceDescription_with_underscores>_<VolumeSerialDecimal>
#  which gives us both a human-readable device description AND the
#  filesystem volume serial number (the 8-char hex shown by "vol" / "dir").
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class EMDEntry:
    description: str    # device description extracted from key name
    vol_serial:  str    # volume serial as 8-char uppercase hex (e.g. "A1B2C3D4")


def parse_emdmgmt(ctx: RegistryContext) -> dict[str, EMDEntry]:
    """
    Returns { vol_serial_hex : EMDEntry }.

    Also checks for an explicit VolumeSerialNumber REG_DWORD value inside
    each subkey, which is more reliable than parsing the key name alone.
    """
    entries: dict[str, EMDEntry] = {}
    key = ctx.try_open_lm(REG_EMDMGMT)
    if key is None:
        return entries

    for subkey in key.subkeys():
        name = subkey.name

        # ── Method 1: explicit VolumeSerialNumber DWORD value ─────────────
        vsn = subkey.value("VolumeSerialNumber")
        if isinstance(vsn, int):
            hex_serial = f"{vsn & 0xFFFFFFFF:08X}"
            desc = name.replace("_", " ").strip()
            entries[hex_serial] = EMDEntry(description=desc, vol_serial=hex_serial)
            subkey.close()
            continue

        # ── Method 2: parse the trailing decimal from the key name ─────────
        # Windows appends "_<VolumeSerial_as_decimal>" at the end.
        m = re.search(r"_(\d{5,})$", name)
        if m:
            try:
                dec_val = int(m.group(1))
                hex_serial = f"{dec_val & 0xFFFFFFFF:08X}"
                desc = name[: m.start()].replace("_", " ").strip() or name
                entries[hex_serial] = EMDEntry(description=desc, vol_serial=hex_serial)
            except (ValueError, OverflowError):
                pass

        subkey.close()

    key.close()
    return entries


# ════════════════════════════════════════════════════════════════════════════
#  MOUNTED DEVICES PARSER  — Binary Decoding & Correlation
#
#  MountedDevices stores two kinds of values:
#    \DosDevices\X:          → which disk/partition is that drive letter
#    \??\Volume{GUID}        → which disk/partition is that volume GUID
#
#  Binary data format:
#    MBR-style (12 bytes): disk_signature[4LE] + partition_offset[8LE]
#    GPT-style  (>8 bytes, starts "DMIO:ID:"): magic[8] + volume_guid[16]
#
#  By comparing the binary content across both value types we can map:
#    drive_letter ↔ volume_GUID ↔ disk_signature
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class MountedEntry:
    raw_name:        str         # original registry value name
    disk_sig:        str         # 8-char hex MBR signature, or ""
    partition_offset:int         # MBR partition byte offset, or 0
    volume_guid:     str         # "{xxxxxxxx-...}" if DMIO/GPT, or ""
    drive_letter:    str         # "E:" if from \DosDevices\X:, else ""
    raw_hex:         str         # full binary as hex (for display/debug)


def _parse_dmio_guid(data: bytes) -> str:
    """
    Extract the volume GUID from a DMIO-format MountedDevices binary value.
    DMIO format: b'DMIO:ID:' (8) + 16-byte GUID in MS binary layout.
    Returns formatted GUID string "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}" or "".
    """
    if len(data) < 24 or data[:8] != b"DMIO:ID:":
        return ""
    g = data[8:24]
    try:
        # Microsoft binary GUID: first 3 fields are little-endian
        p1 = struct.unpack_from("<IHH", g, 0)
        p2 = g[8:10].hex()
        p3 = g[10:16].hex()
        return (f"{{{p1[0]:08x}-{p1[1]:04x}-{p1[2]:04x}-{p2[:2]}{p2[2:]}-{p3}}}").upper()
    except struct.error:
        return ""


def parse_mounted_devices(ctx: RegistryContext) -> dict[str, MountedEntry]:
    """
    Decode every value in HKLM\\SYSTEM\\MountedDevices.

    Returns { value_name : MountedEntry } — includes both \\DosDevices\\X:
    and \\??\\Volume{GUID} entries so callers can cross-reference them.
    """
    entries: dict[str, MountedEntry] = {}
    key = ctx.try_open_lm(REG_MOUNTED)
    if key is None:
        return entries

    for val_name, data in key.values():
        if not isinstance(data, bytes) or len(data) < 12:
            continue

        entry = MountedEntry(
            raw_name=val_name, disk_sig="", partition_offset=0,
            volume_guid="", drive_letter="", raw_hex=data.hex().upper())

        # Extract drive letter if this is a \DosDevices\X: value
        m = re.match(r"\\DosDevices\\([A-Za-z]:)$", val_name)
        if m:
            entry.drive_letter = m.group(1).upper()

        if data[:8] == b"DMIO:ID:":
            # ── GPT / Dynamic Disk style ─────────────────────────────────
            entry.volume_guid = _parse_dmio_guid(data)
        elif len(data) >= 12:
            # ── MBR style: 4-byte disk sig + 8-byte partition offset ─────
            entry.disk_sig        = f"{struct.unpack_from('<I', data, 0)[0]:08X}"
            entry.partition_offset = struct.unpack_from("<Q", data, 4)[0]

        # Extract GUID from \??\Volume{GUID} value names
        vm = re.search(r"\{[0-9a-f-]{36}\}", val_name, re.IGNORECASE)
        if vm and not entry.volume_guid:
            entry.volume_guid = vm.group(0).upper()

        entries[val_name] = entry

    key.close()

    # ── Build a signature → drive_letter lookup ──────────────────────────
    # Used later so we can assign drive letters to USB devices
    # by matching disk signatures / volume GUIDs.
    sig_to_letter:  dict[str, str] = {}
    guid_to_letter: dict[str, str] = {}

    for e in entries.values():
        if e.drive_letter:
            if e.disk_sig:
                sig_to_letter[e.disk_sig] = e.drive_letter
            if e.volume_guid:
                guid_to_letter[e.volume_guid.upper()] = e.drive_letter

    # Annotate volume-GUID entries that don't already have a drive letter
    # by cross-referencing them with DosDevices entries sharing the same binary
    raw_to_letter: dict[str, str] = {}
    for e in entries.values():
        if e.drive_letter:
            raw_to_letter[e.raw_hex] = e.drive_letter

    for e in entries.values():
        if not e.drive_letter and e.raw_hex in raw_to_letter:
            e.drive_letter = raw_to_letter[e.raw_hex]

    return entries


# ════════════════════════════════════════════════════════════════════════════
#  MOUNTPOINTS2 + USER ATTRIBUTION PARSER
#
#  HKCU\...\MountPoints2 stores a subkey for every volume GUID the
#  logged-in user ever accessed.  Correlating these GUIDs with the
#  MountedDevices entries proves that a specific USER accessed the drive,
#  not just that the computer recorded the hardware.
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class UserVolumeInfo:
    username:     str
    volume_guid:  str    # "{xxxxxxxx-...}"
    drive_letter: str    # matched from MountedDevices, or ""


def parse_user_mountpoints(
        ctx: RegistryContext,
        mounted: dict[str, MountedEntry]) -> list[UserVolumeInfo]:
    """
    Collect all volume GUIDs from every user's MountPoints2 key and
    correlate them with MountedDevices to find the drive letter.

    Returns a flat list of UserVolumeInfo records.
    """
    infos: list[UserVolumeInfo] = []

    # Build a GUID (uppercase) → drive_letter map from MountedDevices
    guid_to_letter: dict[str, str] = {}
    for entry in mounted.values():
        if entry.volume_guid and entry.drive_letter:
            # Normalise to uppercase so comparisons never fail on case
            guid_to_letter[entry.volume_guid.upper()] = entry.drive_letter

    # raw_hex → drive_letter (for binary equality fallback)
    raw_to_letter: dict[str, str] = {}
    for e in mounted.values():
        if e.drive_letter:
            raw_to_letter[e.raw_hex] = e.drive_letter

    # Build a case-insensitive map for \??\Volume{GUID} lookups.
    # Windows stores these with inconsistent casing between hives.
    vol_key_to_entry: dict[str, MountedEntry] = {}
    for k, e in mounted.items():
        vol_key_to_entry[k.upper()] = e

    # Gather volume GUIDs from MountPoints2 for every user
    for key, username in ctx.get_all_users_cu(REG_MNTPNT):
        with key:
            for subkey in key.subkeys():
                guid = subkey.name
                if not (guid.startswith("{") and guid.endswith("}")):
                    subkey.close()
                    continue

                guid_upper = guid.upper()

                # Pass 1: direct GUID → letter from MountedDevices
                drive_letter = guid_to_letter.get(guid_upper, "")

                # Pass 2: look up \??\Volume{GUID} entry (case-insensitive)
                if not drive_letter:
                    vol_key = f"\\??\\Volume{guid_upper}"
                    mt_entry = vol_key_to_entry.get(vol_key)
                    if mt_entry:
                        drive_letter = (mt_entry.drive_letter or
                                        raw_to_letter.get(mt_entry.raw_hex, ""))

                # Pass 3: fall back to any MountedDevices entry sharing raw bytes
                if not drive_letter:
                    # Find any DosDevices entry whose volume_guid matches
                    for e in mounted.values():
                        if e.volume_guid and e.volume_guid.upper() == guid_upper:
                            drive_letter = e.drive_letter or drive_letter

                infos.append(UserVolumeInfo(
                    username=username,
                    volume_guid=guid_upper,
                    drive_letter=drive_letter,
                ))
                subkey.close()

    return infos


# ════════════════════════════════════════════════════════════════════════════
#  VOLUME GUID ↔ USB DEVICE CORRELATION
#  Uses DeviceClasses\{VOLUME_GUID} to link a USBSTOR serial number
#  to the Windows-assigned volume GUID (and therefore to a drive letter
#  and user-attribution data).
# ════════════════════════════════════════════════════════════════════════════

def build_serial_to_volume_guid(ctx: RegistryContext) -> dict[str, str]:
    """
    Walk HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\{VOLUME_IFACE}.
    Each subkey name encodes the full device path, which includes the USB
    serial number for USBSTOR devices.  The subkey name also contains the
    volume GUID (the '{...}' immediately before the class GUID).

    Example key name:
      ##?#STORAGE#Volume#{a1b2c3d4-...}#{53f5630d-...}

    For USBSTOR-attached volumes the pattern is:
      ##?#STORAGE#Volume#_??_USBSTOR#Disk&...#<SERIAL>&0#{...}

    Returns { UPPERCASE_SERIAL : "{volume-GUID}" }
    """
    mapping: dict[str, str] = {}
    path = f"{REG_DEVCLASSES}\\{GUID_VOLUME_IFACE}"
    key  = ctx.try_open_lm(path)
    if key is None:
        return mapping

    for subkey in key.subkeys():
        # The subkey name IS the device path with \ replaced by #
        # Extract serial: last component before the final &0#...
        name_upper = subkey.name.upper()

        # Volume GUID: the {GUID} that appears right before the class GUID
        guids = re.findall(r"\{[0-9A-F-]{36}\}", name_upper)
        if len(guids) >= 2:
            vol_guid = guids[-2]   # second-to-last: the volume GUID
        elif guids:
            vol_guid = guids[-1]
        else:
            vol_guid = ""

        # Serial number: look for the USB serial pattern (#<serial>&0#).
        # Use a permissive pattern — real serials can contain dashes, dots,
        # mixed case and other printable chars; [A-Z0-9]{8,} was too strict.
        ser_match = re.search(r"#([^#&]{4,})&0#", subkey.name, re.IGNORECASE)
        if ser_match and vol_guid:
            mapping[ser_match.group(1).upper()] = vol_guid

        subkey.close()

    key.close()
    return mapping


# ════════════════════════════════════════════════════════════════════════════
#  USBSTOR PARSER  — Mass Storage Devices
# ════════════════════════════════════════════════════════════════════════════

def parse_usbstor(ctx: RegistryContext,
                  setupapi_cache: dict[str, str]) -> list[USBDevice]:
    """
    Mine HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR.

    Two-level hierarchy:
      USBSTOR
        └─ Disk&Ven_<VEN>&Prod_<PROD>&Rev_<REV>          ← device-class key
               └─ <SerialNumber>&0   (or &1 for real)    ← instance key
                      └─ Properties\\{83da6326-...}\\...  ← DEVPKEY timestamps
    """
    devices: list[USBDevice] = []
    root = ctx.try_open_lm(REG_USBSTOR)
    if root is None:
        return devices

    for class_key in root.subkeys():
        class_name = class_key.name

        # Parse vendor / product / revision from class key name
        ven_m  = re.search(r"Ven_([^&]+)",  class_name)
        prod_m = re.search(r"Prod_([^&]+)", class_name)
        rev_m  = re.search(r"Rev_([^&]+)",  class_name)
        raw_vendor  = ven_m.group(1).replace("_", " ").strip()  if ven_m  else ""
        raw_product = prod_m.group(1).replace("_", " ").strip() if prod_m else ""
        raw_rev     = rev_m.group(1)                             if rev_m  else ""

        for inst_key in class_key.subkeys():
            serial_raw = inst_key.name
            dev = USBDevice()
            dev.device_class     = "Mass Storage"
            dev.serial_number    = serial_raw.split("&")[0]   # strip "&0" suffix
            dev.disk_id          = serial_raw                  # full instance ID
            dev.rev              = raw_rev
            dev.raw_key          = f"USBSTOR\\{class_name}\\{serial_raw}"
            dev.vendor_name      = raw_vendor  or "Unknown"
            dev.vendor_id        = "—"   # USBSTOR encodes vendor as text, not VID
            dev.product_id       = "—"
            dev.friendly_name    = ""
            dev.hardware_ids     = inst_key.value("HardwareID", default="")
            dev.service          = inst_key.value("Service", default="")
            dev.parent_id_prefix = inst_key.value("ParentIdPrefix", default="")

            # ── Friendly name (multiple fallbacks) ──────────────────────
            fn = inst_key.value("FriendlyName", default="")
            if isinstance(fn, bytes):
                try:
                    fn = fn.decode("utf-16-le").rstrip("\x00")
                except Exception:
                    fn = ""
            dev.friendly_name = str(fn) if fn else f"{raw_vendor} {raw_product}".strip()

            # ── Timestamps ───────────────────────────────────────────────
            # Priority 1: device Properties DEVPKEY subkeys (most accurate)
            ts = _read_devpkey_timestamps(inst_key)
            dev.first_connected   = ts.get("first_connected", "")
            dev.last_connected    = ts.get("last_connected", "")
            dev.last_disconnected = ts.get("last_disconnected", "")

            # Priority 2: SetupAPI log fallback for first-connected
            if not dev.first_connected:
                for key_fragment, ts_str in setupapi_cache.items():
                    if (serial_raw.upper() in key_fragment or
                            class_name.upper() in key_fragment):
                        dev.first_connected = ts_str
                        break

            # Priority 3: key LastWrite time as last-connected fallback
            if not dev.last_connected:
                dev.last_connected = inst_key.last_write_str()

            inst_key.close()
            devices.append(dev)

        class_key.close()

    root.close()
    return devices


# ════════════════════════════════════════════════════════════════════════════
#  USB ENUM PARSER  — All USB Devices (HID, cameras, phones, hubs…)
# ════════════════════════════════════════════════════════════════════════════

def parse_usb_enum(ctx: RegistryContext,
                   setupapi_cache: dict[str, str]) -> list[USBDevice]:
    """
    Mine HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB.

    Structure:
      USB
        └─ VID_xxxx&PID_yyyy[&MI_zz]     ← device-class key
               └─ <instance-id>           ← per-connection key
    """
    devices: list[USBDevice] = []
    root = ctx.try_open_lm(REG_USB)
    if root is None:
        return devices

    for class_key in root.subkeys():
        class_name = class_key.name
        if "ROOT_HUB" in class_name.upper():
            class_key.close()
            continue

        vid, pid = parse_vid_pid(class_name)

        for inst_key in class_key.subkeys():
            instance_id = inst_key.name
            dev = USBDevice()
            dev.vendor_id    = vid
            dev.product_id   = pid
            dev.vendor_name  = resolve_vendor(vid)
            dev.device_class = "USB Device"
            dev.disk_id      = instance_id
            dev.serial_number = instance_id
            dev.raw_key      = f"USB\\{class_name}\\{instance_id}"
            dev.service      = inst_key.value("Service", default="")
            dev.hardware_ids = inst_key.value("HardwareID", default="")

            fn = inst_key.value("FriendlyName", default="") or \
                 inst_key.value("DeviceDesc",   default="")
            if isinstance(fn, bytes):
                try:
                    fn = fn.decode("utf-16-le").rstrip("\x00")
                except Exception:
                    fn = ""
            dev.friendly_name = str(fn) if fn else f"USB {dev.vendor_name} [{vid}:{pid}]"

            # ── Timestamps ───────────────────────────────────────────────
            ts = _read_devpkey_timestamps(inst_key)
            dev.first_connected   = ts.get("first_connected", "")
            dev.last_connected    = ts.get("last_connected", "")
            dev.last_disconnected = ts.get("last_disconnected", "")

            if not dev.first_connected:
                for key_fragment, ts_str in setupapi_cache.items():
                    if instance_id.upper() in key_fragment:
                        dev.first_connected = ts_str
                        break

            if not dev.last_connected:
                dev.last_connected = inst_key.last_write_str()

            inst_key.close()
            devices.append(dev)

        class_key.close()

    root.close()
    return devices


# ════════════════════════════════════════════════════════════════════════════
#  ENRICHMENT  — Cross-reference all parsed data into USBDevice records
# ════════════════════════════════════════════════════════════════════════════

def _match_emdmgmt(dev: "USBDevice",
                   emdmgmt: dict[str, "EMDEntry"]) -> tuple[str, str]:
    """
    Try to find the best EMDMgmt entry for a device.  Returns
    (vol_serial_hex, description) or ("", "") if nothing matches.

    The EMDMgmt key description is the hardware friendly name with
    underscores instead of spaces, e.g.:
        "SanDisk Ultra USB 3 0"   ← from "SanDisk_Ultra_USB_3.0_…"
        "Kingston DataTraveler 100 G3 USB Device"

    Four passes, stopping at the first hit:
      Pass 1 – exact friendly_name match (after normalising punctuation)
      Pass 2 – all significant words of friendly_name present in description
      Pass 3 – all significant words of vendor_name present in description
      Pass 4 – any single long word (≥5 chars) of vendor_name present
    """
    def _normalise(s: str) -> str:
        """Lowercase, replace punctuation/underscores with space, collapse spaces."""
        s = re.sub(r"[_.\-/\\]", " ", s.lower())
        return re.sub(r"\s+", " ", s).strip()

    def _sig_words(s: str, min_len: int = 4) -> list[str]:
        """Significant words: length ≥ min_len, not generic USB noise."""
        noise = {"usb", "device", "disk", "flash", "drive", "storage",
                 "media", "card", "reader", "mass", "removable"}
        return [w for w in _normalise(s).split()
                if len(w) >= min_len and w not in noise]

    friendly_norm = _normalise(dev.friendly_name)
    vendor_norm   = _normalise(dev.vendor_name)

    friendly_words = _sig_words(dev.friendly_name, min_len=4)
    vendor_words   = _sig_words(dev.vendor_name,   min_len=5)

    best_ser, best_desc = "", ""
    best_pass = 99

    for hex_ser, emd in emdmgmt.items():
        desc_norm  = _normalise(emd.description)
        desc_words = _normalise(emd.description).split()

        # Pass 1: exact normalised match
        if friendly_norm and friendly_norm == desc_norm:
            return emd.vol_serial, emd.description

        # Pass 2: all friendly_name significant words present in description
        if (friendly_words and
                all(fw in desc_norm for fw in friendly_words)):
            if best_pass > 2:
                best_pass, best_ser, best_desc = 2, emd.vol_serial, emd.description

        # Pass 3: all vendor significant words present in description
        elif (vendor_words and
              all(vw in desc_norm for vw in vendor_words)):
            if best_pass > 3:
                best_pass, best_ser, best_desc = 3, emd.vol_serial, emd.description

        # Pass 4: at least one long vendor word present (loose fallback)
        elif (vendor_words and
              any(vw in desc_norm for vw in vendor_words if len(vw) >= 5)):
            if best_pass > 4:
                best_pass, best_ser, best_desc = 4, emd.vol_serial, emd.description

    return best_ser, best_desc


def enrich_devices(
        devices:       list[USBDevice],
        emdmgmt:       dict[str, EMDEntry],
        mounted:       dict[str, MountedEntry],
        user_vols:     list[UserVolumeInfo],
        serial_to_vol: dict[str, str]) -> None:
    """
    Populate volume_name, volume_serial, drive_letter, disk_signature,
    volume_guid and user_accounts on each device by cross-referencing
    EMDMgmt, MountedDevices, MountPoints2, and DeviceClasses data.
    """

    # ── Step 1: build quick-lookup maps ──────────────────────────────────

    # vol_serial_hex → EMDEntry
    # (serial is already the key in emdmgmt)

    # vol_guid (UPPER) → drive_letter  from mounted entries
    vol_guid_to_letter: dict[str, str] = {}
    sig_to_letter:      dict[str, str] = {}
    for e in mounted.values():
        if e.drive_letter:
            if e.volume_guid:
                vol_guid_to_letter[e.volume_guid.upper()] = e.drive_letter
            if e.disk_sig:
                sig_to_letter[e.disk_sig.upper()] = e.drive_letter

    # vol_guid → [username]
    vol_guid_to_users: dict[str, list[str]] = {}
    for uv in user_vols:
        key = uv.volume_guid.upper()
        vol_guid_to_users.setdefault(key, []).append(uv.username)

    # ── Step 2: enrich each device ───────────────────────────────────────
    for dev in devices:

        # ── Volume GUID via DeviceClasses serial mapping ─────────────────
        # serial_to_vol maps UPPERCASE_SERIAL → volume_guid
        if not dev.volume_guid and dev.serial_number:
            vol_guid = serial_to_vol.get(dev.serial_number.upper(), "")
            if not vol_guid and dev.disk_id:
                vol_guid = serial_to_vol.get(dev.disk_id.upper(), "")
            dev.volume_guid = vol_guid

        # ── Drive letter (GUID path) ──────────────────────────────────────
        if not dev.drive_letter and dev.volume_guid:
            dev.drive_letter = vol_guid_to_letter.get(
                dev.volume_guid.upper(), "")

        # ── Drive letter (disk signature path for MBR disks) ─────────────
        if not dev.drive_letter and dev.disk_signature:
            dev.drive_letter = sig_to_letter.get(dev.disk_signature.upper(), "")

        # ── Volume name & serial from EMDMgmt ─────────────────────────────
        # EMDMgmt key description = hardware friendly name (e.g. "SanDisk
        # Ultra USB 3.0") with underscores replacing spaces.  We try three
        # progressively looser passes so we never miss a match.
        if not dev.volume_serial and not dev.volume_name and emdmgmt:
            candidate_ser, candidate_name = _match_emdmgmt(dev, emdmgmt)
            if candidate_ser:
                dev.volume_serial = candidate_ser
                dev.volume_name   = candidate_name

        # ── User attribution ──────────────────────────────────────────────
        if dev.volume_guid:
            users = vol_guid_to_users.get(dev.volume_guid.upper(), [])
            if users:
                dev.user_accounts = ", ".join(sorted(set(users)))

        # ── Disk signature from MountedDevices ───────────────────────────
        if not dev.disk_signature and dev.volume_guid:
            vol_key = f"\\??\\Volume{dev.volume_guid}"
            if vol_key in mounted:
                dev.disk_signature = mounted[vol_key].disk_sig


# ════════════════════════════════════════════════════════════════════════════
#  MAIN SCANNER  — Orchestrates all parsing steps for one scan run
# ════════════════════════════════════════════════════════════════════════════

class USBScanner:
    """
    Runs the full forensic scan using the supplied RegistryContext.
    Designed to be called from a background thread.
    """

    def __init__(self,
                 ctx:         RegistryContext,
                 progress_cb: object = None,
                 status_cb:   object = None):
        self._ctx      = ctx
        self._progress = progress_cb or (lambda v: None)
        self._status   = status_cb   or (lambda s: None)

    def scan(self) -> tuple[list[USBDevice], list[str]]:
        """Return (devices, warnings)."""
        warnings: list[str] = []

        def warn(msg: str):
            warnings.append(msg)

        # ── 1. SetupAPI log (first-install timestamps) ────────────────────
        self._status("Parsing SetupAPI device log…")
        self._progress(8)
        setupapi = {}
        try:
            if self._ctx.live:          # log only makes sense on live system
                setupapi = parse_setupapi_log()
        except Exception as exc:
            warn(f"SetupAPI log: {exc}")

        # ── 2. USBSTOR ────────────────────────────────────────────────────
        self._status("Scanning USBSTOR hive…")
        self._progress(20)
        all_devices: list[USBDevice] = []
        try:
            all_devices.extend(parse_usbstor(self._ctx, setupapi))
        except PermissionError:
            warn("USBSTOR: Access denied — try Run as Administrator.")
        except Exception as exc:
            warn(f"USBSTOR: {exc}")

        # ── 3. USB Enum ───────────────────────────────────────────────────
        self._status("Scanning USB enum hive…")
        self._progress(38)
        try:
            all_devices.extend(parse_usb_enum(self._ctx, setupapi))
        except PermissionError:
            warn("USB enum: Access denied — try Run as Administrator.")
        except Exception as exc:
            warn(f"USB enum: {exc}")

        # ── 4. EMDMgmt (volume names / serials) ───────────────────────────
        self._status("Parsing EMDMgmt (volume info)…")
        self._progress(52)
        emdmgmt: dict[str, EMDEntry] = {}
        try:
            emdmgmt = parse_emdmgmt(self._ctx)
        except Exception as exc:
            warn(f"EMDMgmt: {exc}")

        # ── 5. MountedDevices (binary decode) ─────────────────────────────
        self._status("Decoding MountedDevices binary data…")
        self._progress(63)
        mounted: dict[str, MountedEntry] = {}
        try:
            mounted = parse_mounted_devices(self._ctx)
        except Exception as exc:
            warn(f"MountedDevices: {exc}")

        # ── 6. MountPoints2 (user attribution) ────────────────────────────
        self._status("Parsing MountPoints2 (user attribution)…")
        self._progress(74)
        user_vols: list[UserVolumeInfo] = []
        try:
            user_vols = parse_user_mountpoints(self._ctx, mounted)
        except Exception as exc:
            warn(f"MountPoints2: {exc}")

        # ── 7. DeviceClasses (serial → volume GUID) ───────────────────────
        self._status("Correlating DeviceClasses…")
        self._progress(83)
        serial_to_vol: dict[str, str] = {}
        try:
            serial_to_vol = build_serial_to_volume_guid(self._ctx)
        except Exception as exc:
            warn(f"DeviceClasses: {exc}")

        # ── 8. Cross-reference enrichment ────────────────────────────────
        self._status("Cross-referencing all sources…")
        self._progress(90)
        try:
            enrich_devices(all_devices, emdmgmt, mounted, user_vols, serial_to_vol)
        except Exception as exc:
            warn(f"Enrichment: {exc}")

        # ── 9. Deduplication ──────────────────────────────────────────────
        self._status("Deduplicating…")
        self._progress(96)
        seen:   set[tuple] = set()
        unique: list[USBDevice] = []
        for dev in all_devices:
            key = (dev.serial_number, dev.vendor_id, dev.product_id,
                   dev.friendly_name)
            if key not in seen:
                seen.add(key)
                unique.append(dev)

        self._status(f"Done — {len(unique)} unique device(s) found.")
        self._progress(100)
        return unique, warnings


# ════════════════════════════════════════════════════════════════════════════
#  EXPORT HELPERS
# ════════════════════════════════════════════════════════════════════════════

EXPORT_HEADERS = [
    "Friendly Name", "Volume Name", "Vendor Name", "VID", "PID",
    "Serial Number", "Volume Serial", "Drive Letter",
    "First Connected", "Last Connected", "Last Disconnected",
    "Users", "Device Class", "Disk Signature", "Volume GUID",
    "ParentIdPrefix", "Registry Key",
]


def _device_export_row(dev: USBDevice) -> list:
    return [
        dev.friendly_name, dev.volume_name, dev.vendor_name,
        dev.vendor_id, dev.product_id, dev.serial_number,
        dev.volume_serial, dev.drive_letter,
        dev.first_connected, dev.last_connected, dev.last_disconnected,
        dev.user_accounts, dev.device_class, dev.disk_signature,
        dev.volume_guid, dev.parent_id_prefix, dev.raw_key,
    ]


def export_csv(devices: list[USBDevice], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(EXPORT_HEADERS)
        for d in devices:
            w.writerow(_device_export_row(d))


def export_json(devices: list[USBDevice], path: str) -> None:
    rows = [dict(zip(EXPORT_HEADERS, _device_export_row(d))) for d in devices]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=2, ensure_ascii=False)


def export_txt(devices: list[USBDevice], path: str) -> None:
    sep = "─" * 72
    lines = [
        "═" * 72,
        f"  {APP_TITLE}  v{APP_VER}  —  USB Registry Forensic Report",
        f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Host      : {os.environ.get('COMPUTERNAME', 'Unknown')}",
        f"  Devices   : {len(devices)}",
        "═" * 72, "",
    ]
    for i, d in enumerate(devices, 1):
        lines += [
            f"[{i:03d}]  {d.friendly_name}",
            sep,
            f"  Volume Name      : {d.volume_name      or '—'}",
            f"  Volume Serial    : {d.volume_serial     or '—'}",
            f"  Vendor / Name    : {d.vendor_name} (VID {d.vendor_id} / PID {d.product_id})",
            f"  Serial Number    : {d.serial_number     or 'N/A'}",
            f"  Drive Letter     : {d.drive_letter      or '—'}",
            f"  Disk Signature   : {d.disk_signature    or '—'}",
            f"  Volume GUID      : {d.volume_guid       or '—'}",
            f"  ParentIdPrefix   : {d.parent_id_prefix  or '—'}",
            f"  First Connected  : {d.first_connected   or 'Unknown'}",
            f"  Last Connected   : {d.last_connected    or 'Unknown'}",
            f"  Last Disconnected: {d.last_disconnected or 'Unknown'}",
            f"  Users            : {d.user_accounts     or '—'}",
            f"  Device Class     : {d.device_class}",
            f"  Registry Key     : {d.raw_key}",
            "",
        ]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


# ════════════════════════════════════════════════════════════════════════════
#  GUI  — Main Application Window
# ════════════════════════════════════════════════════════════════════════════

class USBRegParseApp(tk.Tk):
    r"""
    Main window layout:

      ┌──────────────────────────────────────────────────────────┐
      │  HEADER  (logo · title · scan · export buttons)         │
      ├──────────────────────────────────────────────────────────┤
      │  MODE SELECTOR  [● Live Scan]  [○ Offline / Hive Files] │
      ├──────────────────────────────────────────────────────────┤
      │  HIVE LOADER  (shown only in Offline mode)              │
      │    SYSTEM hive  [path…]  [Browse]                       │
      │    SOFTWARE hive[path…]  [Browse]                       │
      │    NTUSER.DAT   [path…]  [Browse] [+ Add]               │
      ├──────────────────────────────────────────────────────────┤
      │  FILTER BAR  (search · class · vendor dropdowns)        │
      ├──────────────────────────────────────────────────────────┤
      │  MAIN TABLE  (sortable Treeview)                        │
      ├──────────────────────────────────────────────────────────┤
      │  DETAIL PANE  (expanded info + copy buttons)            │
      ├──────────────────────────────────────────────────────────┤
      │  STATUS BAR  (progress · message · host)                │
      └──────────────────────────────────────────────────────────┘
    """

    # Table column definitions: (header, width, anchor)
    COLUMNS = [
        ("Friendly Name",    230, "w"),
        ("Volume Name",      130, "w"),
        ("Vendor",           130, "w"),
        ("VID",               58, "center"),
        ("PID",               58, "center"),
        ("Serial Number",    155, "w"),
        ("Vol Serial",        90, "center"),
        ("Drive",             52, "center"),
        ("First Connected",  165, "center"),
        ("Last Connected",   165, "center"),
        ("Last Disconnected",165, "center"),
        ("Users",            110, "w"),
        ("Class",            110, "w"),
    ]

    def __init__(self):
        super().__init__()
        self.title(f"{APP_TITLE} v{APP_VER} — {APP_SUBHEAD}")
        self.geometry("1400x860")
        self.minsize(1000, 640)
        self.configure(bg=CLR_BG)

        self._all_devices:      list[USBDevice] = []
        self._filtered_devices: list[USBDevice] = []
        self._sort_col  = ""
        self._sort_asc  = True
        self._scan_thread: threading.Thread | None = None

        # Offline hive paths
        self._sys_path_var      = tk.StringVar()
        self._soft_path_var     = tk.StringVar()
        self._ntuser_entries:   list[tuple[tk.StringVar, tk.StringVar]] = []  # (path, user)
        self._ntuser_frame:     tk.Frame | None = None

        self._setup_styles()
        self._build_header()
        self._build_mode_selector()
        self._build_hive_loader()
        self._build_filter_bar()
        self._build_table()
        self._build_detail_pane()
        self._build_status_bar()

        # Keyboard shortcuts
        self.bind("<F5>",        lambda _: self._scan())
        self.bind("<Control-e>", lambda _: self._export())
        self.bind("<Escape>",    lambda _: self._clear_filter())

        self._set_status("Ready — press F5 or click Scan to begin.", "info")

    # ── Styles ───────────────────────────────────────────────────────────────

    def _setup_styles(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".",
            background=CLR_BG, foreground=CLR_TEXT,
            fieldbackground=CLR_SURFACE, bordercolor=CLR_BORDER,
            troughcolor=CLR_SURFACE, font=FONT_BODY)
        s.configure("Treeview",
            background=CLR_SURFACE, foreground=CLR_TEXT,
            fieldbackground=CLR_SURFACE, rowheight=26, font=FONT_BODY,
            bordercolor=CLR_BORDER, relief="flat")
        s.configure("Treeview.Heading",
            background=CLR_SURFACE2, foreground=CLR_ACCENT,
            font=FONT_HEAD, relief="flat")
        s.map("Treeview",
            background=[("selected", CLR_SELECT)],
            foreground=[("selected", CLR_TEXT)])
        s.map("Treeview.Heading",
            background=[("active", CLR_BORDER)])
        s.configure("Accent.Horizontal.TProgressbar",
            troughcolor=CLR_SURFACE, background=CLR_ACCENT,
            bordercolor=CLR_BORDER)
        s.configure("Accent.TButton",
            background=CLR_ACCENT, foreground="#000000",
            font=("Segoe UI Semibold", 10), relief="flat", padding=(14, 6))
        s.map("Accent.TButton",
            background=[("active", "#00b8cc"), ("disabled", CLR_BORDER)],
            foreground=[("disabled", CLR_MUTED)])
        s.configure("Flat.TButton",
            background=CLR_SURFACE, foreground=CLR_TEXT,
            font=FONT_BODY, relief="flat", padding=(10, 6))
        s.map("Flat.TButton",
            background=[("active", CLR_BORDER)])
        s.configure("Offline.TButton",
            background=CLR_ACCENT3, foreground="#ffffff",
            font=("Segoe UI Semibold", 10), relief="flat", padding=(14, 6))
        s.map("Offline.TButton",
            background=[("active", "#8a5cf6"), ("disabled", CLR_BORDER)])
        s.configure("TCombobox",
            fieldbackground=CLR_SURFACE, foreground=CLR_TEXT,
            background=CLR_SURFACE, arrowcolor=CLR_ACCENT)
        s.map("TCombobox", fieldbackground=[("readonly", CLR_SURFACE)],
              foreground=[("readonly", CLR_TEXT)])
        s.configure("TScrollbar",
            background=CLR_SURFACE, troughcolor=CLR_BG,
            bordercolor=CLR_BORDER, arrowcolor=CLR_MUTED)
        s.configure("TRadiobutton",
            background=CLR_SURFACE, foreground=CLR_TEXT, font=FONT_BODY)
        s.map("TRadiobutton",
            background=[("active", CLR_SURFACE)],
            foreground=[("active", CLR_ACCENT)])

    # ── Header ────────────────────────────────────────────────────────────────

    def _build_header(self):
        hdr = tk.Frame(self, bg=CLR_SURFACE, height=68)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(hdr, text="⚡", font=("Segoe UI", 26),
                 bg=CLR_SURFACE, fg=CLR_ACCENT).pack(side="left", padx=(18, 6), pady=8)

        tf = tk.Frame(hdr, bg=CLR_SURFACE)
        tf.pack(side="left", pady=8)
        tk.Label(tf, text=APP_TITLE, font=FONT_TITLE,
                 bg=CLR_SURFACE, fg=CLR_TEXT).pack(anchor="w")
        tk.Label(tf, text=f"{APP_SUBHEAD}  •  v{APP_VER}",
                 font=FONT_SMALL, bg=CLR_SURFACE, fg=CLR_MUTED).pack(anchor="w")

        bf = tk.Frame(hdr, bg=CLR_SURFACE)
        bf.pack(side="right", padx=18, pady=16)
        self._btn_export = ttk.Button(bf, text="⬇  Export",
            style="Flat.TButton", command=self._export, state="disabled")
        self._btn_export.pack(side="right", padx=(6, 0))
        self._btn_scan = ttk.Button(bf, text="▶  Scan  [F5]",
            style="Accent.TButton", command=self._scan)
        self._btn_scan.pack(side="right")

        tk.Frame(self, bg=CLR_ACCENT, height=2).pack(fill="x")

    # ── Mode selector ─────────────────────────────────────────────────────────

    def _build_mode_selector(self):
        """Radio buttons to toggle between Live and Offline scan modes."""
        mf = tk.Frame(self, bg=CLR_SURFACE, pady=8)
        mf.pack(fill="x")

        tk.Label(mf, text="Scan Mode:", font=FONT_HEAD,
                 bg=CLR_SURFACE, fg=CLR_MUTED).pack(side="left", padx=(18, 8))

        self._mode_var = tk.StringVar(value="live")
        for label, val, clr in [
            ("🔴  Live Registry Scan", "live",    CLR_ACCENT),
            ("💾  Offline Hive Files", "offline", CLR_ACCENT3),
        ]:
            rb = tk.Radiobutton(mf, text=label, variable=self._mode_var,
                                value=val, font=FONT_BODY,
                                bg=CLR_SURFACE, fg=clr,
                                activebackground=CLR_SURFACE, activeforeground=clr,
                                selectcolor=CLR_BG,
                                command=self._on_mode_change)
            rb.pack(side="left", padx=12)

        # Offline-mode note
        self._mode_note = tk.Label(mf,
            text="Offline mode requires: pip install python-registry",
            font=FONT_SMALL, bg=CLR_SURFACE, fg=CLR_WARN)
        if not OFFLINE_AVAILABLE:
            self._mode_note.pack(side="left", padx=18)

        tk.Frame(self, bg=CLR_BORDER, height=1).pack(fill="x")

    def _on_mode_change(self):
        is_offline = self._mode_var.get() == "offline"
        if is_offline and not OFFLINE_AVAILABLE:
            messagebox.showwarning(
                "python-registry Not Found",
                "Offline hive parsing requires the python-registry library.\n\n"
                "Install it with:\n    pip install python-registry\n\n"
                "Then restart USB RegParse.", parent=self)
            self._mode_var.set("live")
            return
        self._hive_loader_frame.pack(fill="x") if is_offline else \
            self._hive_loader_frame.pack_forget()
        # Update scan button style
        style = "Offline.TButton" if is_offline else "Accent.TButton"
        label = "▶  Offline Scan  [F5]" if is_offline else "▶  Scan  [F5]"
        self._btn_scan.configure(style=style, text=label)

    # ── Hive file loader (offline mode) ──────────────────────────────────────

    def _build_hive_loader(self):
        """
        Panel for selecting SYSTEM, SOFTWARE and NTUSER.DAT hive files.
        Hidden by default; shown only when offline mode is selected.
        """
        self._hive_loader_frame = tk.Frame(self, bg=CLR_SURFACE2, pady=10)
        # NOT packed initially — will be shown by _on_mode_change

        tk.Label(self._hive_loader_frame,
                 text="  💾  Offline Hive Files", font=FONT_HEAD,
                 bg=CLR_SURFACE2, fg=CLR_ACCENT3).grid(
                 row=0, column=0, columnspan=4, sticky="w", padx=12, pady=(4, 8))

        def _row(label: str, var: tk.StringVar, row: int, required: bool = False):
            req_star = " *" if required else ""
            tk.Label(self._hive_loader_frame,
                     text=f"{label}{req_star}:", font=FONT_BODY,
                     bg=CLR_SURFACE2, fg=CLR_TEXT, width=14, anchor="e").grid(
                     row=row, column=0, padx=(12, 6), pady=3, sticky="e")
            e = tk.Entry(self._hive_loader_frame, textvariable=var,
                         bg=CLR_SURFACE, fg=CLR_TEXT, insertbackground=CLR_TEXT,
                         relief="flat", font=FONT_MONO, width=52)
            e.grid(row=row, column=1, padx=4, pady=3, sticky="ew")
            ttk.Button(self._hive_loader_frame, text="Browse…",
                       style="Flat.TButton",
                       command=lambda v=var: self._browse_hive(v)).grid(
                       row=row, column=2, padx=6, pady=3)

        _row("SYSTEM hive",   self._sys_path_var,  1, required=True)
        _row("SOFTWARE hive", self._soft_path_var, 2)

        # NTUSER.DAT area with dynamic add rows
        tk.Label(self._hive_loader_frame,
                 text="NTUSER.DAT:", font=FONT_BODY,
                 bg=CLR_SURFACE2, fg=CLR_TEXT, width=14, anchor="e").grid(
                 row=3, column=0, padx=(12, 6), pady=3, sticky="ne")

        self._ntuser_frame = tk.Frame(self._hive_loader_frame, bg=CLR_SURFACE2)
        self._ntuser_frame.grid(row=3, column=1, columnspan=2, sticky="ew", pady=3)

        ttk.Button(self._hive_loader_frame, text="+ Add User",
                   style="Flat.TButton",
                   command=self._add_ntuser_row).grid(
                   row=4, column=1, sticky="w", padx=4, pady=(0, 6))

        tk.Label(self._hive_loader_frame,
                 text="  * SYSTEM hive is required.  SOFTWARE and NTUSER.DAT are optional.",
                 font=FONT_SMALL, bg=CLR_SURFACE2, fg=CLR_MUTED).grid(
                 row=5, column=0, columnspan=4, sticky="w", padx=12, pady=(0, 4))

        self._hive_loader_frame.columnconfigure(1, weight=1)

        # Add one NTUSER.DAT row by default
        self._add_ntuser_row()

        tk.Frame(self, bg=CLR_BORDER, height=1).pack(fill="x")

    def _browse_hive(self, var: tk.StringVar):
        path = filedialog.askopenfilename(
            parent=self, title="Select Hive File",
            filetypes=[("Registry Hive Files", "SYSTEM SOFTWARE SAM NTUSER.DAT *"),
                       ("All Files", "*.*")])
        if path:
            var.set(path)

    def _browse_ntuser(self, path_var: tk.StringVar, user_var: tk.StringVar):
        """
        Browse for an NTUSER.DAT file and auto-detect the username from its
        file path.  Windows stores user hives at:
          C:\\Users\\<username>\\NTUSER.DAT
        so we look for a 'Users' component in the path and take the next
        component as the username.  Falls back to the parent folder name.
        """
        path = filedialog.askopenfilename(
            parent=self, title="Select NTUSER.DAT",
            filetypes=[("NTUSER.DAT", "NTUSER.DAT NTUSER.DAT.LOG*"),
                       ("All Files", "*.*")])
        if not path:
            return
        path_var.set(path)

        # ── Auto-detect username from path ──────────────────────────────
        p = Path(path)
        parts = p.parts           # e.g. ('C:\\', 'Users', 'Downloads', 'NTUSER.DAT')
        detected = ""
        for i, part in enumerate(parts):
            if part.upper() == "USERS" and i + 1 < len(parts):
                candidate = parts[i + 1]
                # Skip well-known non-user folders
                if candidate.upper() not in ("DEFAULT", "PUBLIC", "ALL USERS",
                                              "DEFAULT USER"):
                    detected = candidate
                    break
        if not detected:
            # Fallback: the parent directory name is usually the username
            detected = p.parent.name

        if detected:
            user_var.set(detected)

    def _add_ntuser_row(self):
        """Add a (hive-path, username) row to the NTUSER.DAT section."""
        if self._ntuser_frame is None:
            return
        path_var = tk.StringVar()
        user_var = tk.StringVar(value=f"User{len(self._ntuser_entries)+1}")
        self._ntuser_entries.append((path_var, user_var))

        rf = tk.Frame(self._ntuser_frame, bg=CLR_SURFACE2)
        rf.pack(fill="x", pady=2)

        tk.Entry(rf, textvariable=path_var, bg=CLR_SURFACE,
                 fg=CLR_TEXT, insertbackground=CLR_TEXT,
                 relief="flat", font=FONT_MONO, width=44).pack(side="left", padx=(0, 4))
        # Use _browse_ntuser (not _browse_hive) so username is auto-detected
        ttk.Button(rf, text="Browse…", style="Flat.TButton",
                   command=lambda pv=path_var, uv=user_var:
                       self._browse_ntuser(pv, uv)).pack(side="left", padx=2)
        tk.Label(rf, text="Username:", font=FONT_SMALL,
                 bg=CLR_SURFACE2, fg=CLR_MUTED).pack(side="left", padx=(10, 4))
        tk.Entry(rf, textvariable=user_var, bg=CLR_SURFACE,
                 fg=CLR_TEXT, insertbackground=CLR_TEXT,
                 relief="flat", font=FONT_BODY, width=14).pack(side="left", padx=2)

    # ── Filter bar ────────────────────────────────────────────────────────────

    def _build_filter_bar(self):
        bar = tk.Frame(self, bg=CLR_BG, pady=7)
        bar.pack(fill="x", padx=14)

        tk.Label(bar, text="🔍", font=FONT_BODY,
                 bg=CLR_BG, fg=CLR_MUTED).pack(side="left")
        tk.Label(bar, text="Search:", font=FONT_BODY,
                 bg=CLR_BG, fg=CLR_MUTED).pack(side="left", padx=(2, 4))

        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._apply_filter())
        tk.Entry(bar, textvariable=self._search_var, width=28,
                 bg=CLR_SURFACE, fg=CLR_TEXT, insertbackground=CLR_TEXT,
                 relief="flat", font=FONT_BODY).pack(side="left", padx=(0, 16), ipady=4)

        for label, attr in [("Class:", "_class_var"), ("Vendor:", "_vendor_var")]:
            tk.Label(bar, text=label, font=FONT_BODY,
                     bg=CLR_BG, fg=CLR_MUTED).pack(side="left")
            var = tk.StringVar(value="All")
            setattr(self, attr, var)
            cb = ttk.Combobox(bar, textvariable=var, values=["All"],
                               width=18, state="readonly")
            cb.pack(side="left", padx=(4, 14), ipady=2)
            cb.bind("<<ComboboxSelected>>", lambda _: self._apply_filter())
            if attr == "_class_var":
                self._class_combo = cb
            else:
                self._vendor_combo = cb

        ttk.Button(bar, text="✕ Clear", style="Flat.TButton",
                   command=self._clear_filter).pack(side="left")

        self._count_label = tk.Label(bar, text="", font=FONT_BODY,
                                      bg=CLR_BG, fg=CLR_ACCENT)
        self._count_label.pack(side="right")

    # ── Main table ────────────────────────────────────────────────────────────

    def _build_table(self):
        frm = tk.Frame(self, bg=CLR_BG)
        frm.pack(fill="both", expand=True, padx=14, pady=(0, 0))

        col_ids = [c[0] for c in self.COLUMNS]
        self._tree = ttk.Treeview(frm, columns=col_ids,
                                   show="headings", selectmode="browse")
        for col_id, width, anchor in self.COLUMNS:
            self._tree.heading(col_id, text=col_id, anchor=anchor,
                               command=lambda c=col_id: self._sort_by(c))
            self._tree.column(col_id, width=width, minwidth=40, anchor=anchor)

        self._tree.tag_configure("odd",   background=CLR_SURFACE,  foreground=CLR_TEXT)
        self._tree.tag_configure("even",  background=CLR_SURFACE2, foreground=CLR_TEXT)
        self._tree.tag_configure("stor",  background=CLR_SURFACE,  foreground=CLR_ACCENT2)
        self._tree.tag_configure("user",  background=CLR_SURFACE2, foreground=CLR_ACCENT)

        vsb = ttk.Scrollbar(frm, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(frm, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        self._tree.pack(fill="both", expand=True)

        self._tree.bind("<<TreeviewSelect>>", self._on_select)
        self._tree.bind("<Double-1>",         self._on_double_click)

    # ── Detail pane ───────────────────────────────────────────────────────────

    def _build_detail_pane(self):
        tk.Frame(self, bg=CLR_BORDER, height=1).pack(fill="x")
        df = tk.Frame(self, bg=CLR_SURFACE, height=172)
        df.pack(fill="x")
        df.pack_propagate(False)

        left = tk.Frame(df, bg=CLR_SURFACE)
        left.pack(side="left", fill="both", expand=True, padx=16, pady=10)
        tk.Label(left, text="Device Details", font=FONT_HEAD,
                 bg=CLR_SURFACE, fg=CLR_ACCENT).grid(
                 row=0, column=0, columnspan=6, sticky="w", pady=(0, 6))

        # Two-column grid of label: value pairs
        detail_fields = [
            ("Device Name",      "det_name"),
            ("Volume Name",      "det_volname"),
            ("Vendor",           "det_vendor"),
            ("VID / PID",        "det_vidpid"),
            ("Serial Number",    "det_serial"),
            ("Volume Serial",    "det_volserial"),
            ("Drive Letter",     "det_drive"),
            ("Disk Signature",   "det_sig"),
            ("Volume GUID",      "det_guid"),
            ("ParentIdPrefix",   "det_prefix"),
            ("First Connected",  "det_first"),
            ("Last Connected",   "det_last"),
            ("Last Disconnected","det_disc"),
            ("Users",            "det_users"),
            ("Service Driver",   "det_service"),
            ("Registry Key",     "det_key"),
        ]
        self._det: dict[str, tk.StringVar] = {}
        for i, (label, var_id) in enumerate(detail_fields):
            row, col_pair = divmod(i, 2)
            col = col_pair * 3
            tk.Label(left, text=f"{label}:", font=FONT_SMALL,
                     bg=CLR_SURFACE, fg=CLR_MUTED, anchor="e",
                     width=16).grid(row=row+1, column=col,   sticky="e", padx=(0,4), pady=1)
            var = tk.StringVar(value="—")
            self._det[var_id] = var
            tk.Label(left, textvariable=var, font=("Consolas", 9),
                     bg=CLR_SURFACE, fg=CLR_TEXT, anchor="w",
                     wraplength=340).grid(row=row+1, column=col+1, sticky="w", pady=1)

        # Action buttons on the right
        right = tk.Frame(df, bg=CLR_SURFACE, width=150)
        right.pack(side="right", fill="y", padx=14, pady=10)
        right.pack_propagate(False)
        tk.Label(right, text="Quick Copy", font=FONT_HEAD,
                 bg=CLR_SURFACE, fg=CLR_ACCENT).pack(anchor="w")
        for btn_label, var_id in [
            ("📋 Name",      "det_name"),
            ("📋 Serial",    "det_serial"),
            ("📋 GUID",      "det_guid"),
            ("📋 Reg Key",   "det_key"),
            ("📋 All Fields","__all__"),
        ]:
            ttk.Button(right, text=btn_label, style="Flat.TButton",
                       command=lambda v=var_id: self._copy_detail(v)).pack(
                       fill="x", pady=3)

    # ── Status bar ────────────────────────────────────────────────────────────

    def _build_status_bar(self):
        tk.Frame(self, bg=CLR_BORDER, height=1).pack(fill="x")
        bar = tk.Frame(self, bg=CLR_SURFACE, height=30)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        self._status_dot = tk.Label(bar, text="●", font=FONT_BODY,
                                     bg=CLR_SURFACE, fg=CLR_MUTED)
        self._status_dot.pack(side="left", padx=(12, 4))
        self._status_lbl = tk.Label(bar, text="", font=FONT_BODY,
                                     bg=CLR_SURFACE, fg=CLR_TEXT)
        self._status_lbl.pack(side="left")

        self._prog_var = tk.DoubleVar(value=0)
        ttk.Progressbar(bar, variable=self._prog_var, maximum=100,
                         style="Accent.Horizontal.TProgressbar",
                         length=180).pack(side="right", padx=12, pady=5)

        host = os.environ.get("COMPUTERNAME", "Unknown")
        mode_lbl = "LIVE" if sys.platform == "win32" else "N/A"
        tk.Label(bar, text=f"🖥  {host}", font=FONT_SMALL,
                 bg=CLR_SURFACE, fg=CLR_MUTED).pack(side="right", padx=12)

    # ── Scan orchestration ────────────────────────────────────────────────────

    def _scan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            return
        if self._mode_var.get() == "offline":
            self._scan_offline()
        else:
            self._scan_live()

    def _scan_live(self):
        """Launch a live registry scan in a background thread."""
        self._pre_scan()
        def _run():
            try:
                ctx = RegistryContext(live=True)
                scanner = USBScanner(ctx,
                    progress_cb=lambda v: self.after(0, lambda: self._prog_var.set(v)),
                    status_cb=lambda s: self.after(0, lambda: self._set_status(s, "info")))
                devices, warnings = scanner.scan()
                self.after(0, lambda: self._on_scan_done(devices, warnings, "live"))
            except Exception as exc:
                tb = traceback.format_exc()
                msg = str(exc)   # capture by value before the except scope exits
                self.after(0, lambda m=msg, t=tb: self._on_scan_err(m, t))
        self._scan_thread = threading.Thread(target=_run, daemon=True)
        self._scan_thread.start()

    def _scan_offline(self):
        """Validate hive paths then launch an offline scan in a background thread."""
        sys_path  = self._sys_path_var.get().strip()
        soft_path = self._soft_path_var.get().strip()
        ntuser_list = [(pv.get().strip(), uv.get().strip())
                       for pv, uv in self._ntuser_entries
                       if pv.get().strip()]

        if not sys_path:
            messagebox.showwarning("Missing SYSTEM Hive",
                "Please select the SYSTEM hive file before scanning.",
                parent=self)
            return
        if not Path(sys_path).exists():
            messagebox.showerror("File Not Found",
                f"SYSTEM hive not found:\n{sys_path}", parent=self)
            return

        self._pre_scan()
        def _run():
            try:
                ctx = RegistryContext(
                    live=False,
                    system_path=sys_path,
                    software_path=soft_path or None,
                    ntuser_paths=ntuser_list or None)
                scanner = USBScanner(ctx,
                    progress_cb=lambda v: self.after(0, lambda: self._prog_var.set(v)),
                    status_cb=lambda s: self.after(0, lambda: self._set_status(s, "info")))
                devices, warnings = scanner.scan()
                self.after(0, lambda: self._on_scan_done(devices, warnings, "offline"))
            except Exception as exc:
                tb = traceback.format_exc()
                msg = str(exc)   # capture by value before the except scope exits
                self.after(0, lambda m=msg, t=tb: self._on_scan_err(m, t))
        self._scan_thread = threading.Thread(target=_run, daemon=True)
        self._scan_thread.start()

    def _pre_scan(self):
        self._btn_scan.configure(state="disabled", text="⏳ Scanning…")
        self._btn_export.configure(state="disabled")
        self._prog_var.set(0)
        self._clear_table()
        self._set_status("Scan starting…", "info")

    def _on_scan_done(self, devices: list[USBDevice],
                       warnings: list[str], mode: str):
        self._all_devices = devices
        self._update_filter_combos()
        self._apply_filter()

        scan_label = "▶  Scan  [F5]" if mode == "live" else "▶  Offline Scan  [F5]"
        scan_style = "Accent.TButton" if mode == "live" else "Offline.TButton"
        self._btn_scan.configure(state="normal", text=scan_label, style=scan_style)
        self._btn_export.configure(state="normal" if devices else "disabled")

        if warnings:
            messagebox.showwarning("Scan Warnings",
                f"{len(warnings)} warning(s):\n\n" + "\n".join(warnings), parent=self)

        level = "ok" if devices else "warn"
        self._set_status(
            f"✔  {len(devices)} device(s) found ({mode} scan).  "
            f"Ctrl+E to export." if devices else "No devices found.", level)

    def _on_scan_err(self, msg: str, detail: str):
        self._btn_scan.configure(state="normal", text="▶  Scan  [F5]",
                                  style="Accent.TButton")
        self._set_status(f"Scan failed: {msg}", "error")
        messagebox.showerror("Scan Error", f"{msg}\n\n{detail}", parent=self)

    # ── Table management ──────────────────────────────────────────────────────

    def _clear_table(self):
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._count_label.configure(text="")
        self._clear_detail()

    def _populate_table(self, devices: list[USBDevice]):
        self._clear_table()
        for i, dev in enumerate(devices):
            if dev.device_class == "Mass Storage":
                tag = "stor"
            elif dev.user_accounts:
                tag = "user"
            else:
                tag = "even" if i % 2 == 0 else "odd"
            self._tree.insert("", "end", iid=str(i), values=dev.as_row(), tags=(tag,))
        self._count_label.configure(text=f"{len(devices)} device(s)")

    def _update_filter_combos(self):
        classes  = sorted({d.device_class for d in self._all_devices if d.device_class})
        vendors  = sorted({d.vendor_name  for d in self._all_devices if d.vendor_name})
        self._class_combo["values"]  = ["All"] + classes
        self._vendor_combo["values"] = ["All"] + vendors
        self._class_var.set("All")
        self._vendor_var.set("All")

    def _apply_filter(self):
        query  = self._search_var.get().lower().strip()
        cls    = self._class_var.get()
        vendor = self._vendor_var.get()
        out = []
        for d in self._all_devices:
            if cls    != "All" and d.device_class != cls:    continue
            if vendor != "All" and d.vendor_name  != vendor: continue
            if query:
                hay = " ".join(str(v) for v in d.as_row()).lower()
                if query not in hay:
                    continue
            out.append(d)
        self._filtered_devices = out
        self._populate_table(out)

    def _clear_filter(self):
        self._search_var.set("")
        self._class_var.set("All")
        self._vendor_var.set("All")
        self._apply_filter()

    # ── Sorting ───────────────────────────────────────────────────────────────

    def _sort_by(self, col: str):
        col_names = [c[0] for c in self.COLUMNS]
        if col not in col_names:
            return
        idx = col_names.index(col)
        if self._sort_col == col:
            self._sort_asc = not self._sort_asc
        else:
            self._sort_col = col
            self._sort_asc = True
        self._filtered_devices.sort(
            key=lambda d: (d.as_row()[idx] or "").lower(),
            reverse=not self._sort_asc)
        self._populate_table(self._filtered_devices)
        arrow = "  ▲" if self._sort_asc else "  ▼"
        for cid, _, anc in self.COLUMNS:
            self._tree.heading(cid,
                text=cid + (arrow if cid == col else ""), anchor=anc)

    # ── Detail pane population ────────────────────────────────────────────────

    def _on_select(self, _=None):
        sel = self._tree.selection()
        if sel:
            idx = int(sel[0])
            if idx < len(self._filtered_devices):
                self._show_detail(self._filtered_devices[idx])

    def _on_double_click(self, _=None):
        sel = self._tree.selection()
        if sel:
            idx = int(sel[0])
            if idx < len(self._filtered_devices):
                self._detail_dialog(self._filtered_devices[idx])

    def _show_detail(self, dev: USBDevice):
        v = self._det
        v["det_name"].set(dev.friendly_name    or "—")
        v["det_volname"].set(dev.volume_name   or "—")
        v["det_vendor"].set(dev.vendor_name    or "—")
        v["det_vidpid"].set(f"{dev.vendor_id} / {dev.product_id}")
        v["det_serial"].set(dev.serial_number  or "—")
        v["det_volserial"].set(dev.volume_serial or "—")
        v["det_drive"].set(dev.drive_letter    or "—")
        v["det_sig"].set(dev.disk_signature    or "—")
        v["det_guid"].set(dev.volume_guid      or "—")
        v["det_prefix"].set(dev.parent_id_prefix or "—")
        v["det_first"].set(dev.first_connected or "—")
        v["det_last"].set(dev.last_connected   or "—")
        v["det_disc"].set(dev.last_disconnected or "—")
        v["det_users"].set(dev.user_accounts   or "—")
        v["det_service"].set(dev.service       or "—")
        v["det_key"].set(dev.raw_key           or "—")

    def _clear_detail(self):
        for var in self._det.values():
            var.set("—")

    def _detail_dialog(self, dev: USBDevice):
        dlg = tk.Toplevel(self)
        dlg.title(f"Full Device Record — {dev.friendly_name}")
        dlg.configure(bg=CLR_BG)
        dlg.geometry("680x560")
        dlg.grab_set()
        tk.Label(dlg, text=dev.friendly_name,
                 font=("Segoe UI Semibold", 14), bg=CLR_BG,
                 fg=CLR_ACCENT, wraplength=640).pack(padx=20, pady=(16,4), anchor="w")
        txt = tk.Text(dlg, bg=CLR_SURFACE, fg=CLR_TEXT,
                      font=("Consolas", 10), relief="flat",
                      borderwidth=0, padx=12, pady=10, wrap="word")
        txt.pack(fill="both", expand=True, padx=16, pady=8)
        rows = [
            ("Device Name",      dev.friendly_name),
            ("Volume Name",      dev.volume_name),
            ("Vendor",           dev.vendor_name),
            ("VID / PID",        f"{dev.vendor_id} / {dev.product_id}"),
            ("Serial Number",    dev.serial_number),
            ("Volume Serial",    dev.volume_serial),
            ("Drive Letter",     dev.drive_letter),
            ("Disk Signature",   dev.disk_signature),
            ("Volume GUID",      dev.volume_guid),
            ("ParentIdPrefix",   dev.parent_id_prefix),
            ("First Connected",  dev.first_connected),
            ("Last Connected",   dev.last_connected),
            ("Last Disconnected",dev.last_disconnected),
            ("Users",            dev.user_accounts),
            ("Device Class",     dev.device_class),
            ("Service Driver",   dev.service),
            ("Hardware IDs",     dev.hardware_ids),
            ("Registry Key",     dev.raw_key),
        ]
        for label, val in rows:
            txt.insert("end", f"{label:20s}: ", "lbl")
            txt.insert("end", f"{val or '—'}\n",  "val")
        txt.tag_configure("lbl", foreground=CLR_MUTED)
        txt.tag_configure("val", foreground=CLR_TEXT)
        txt.configure(state="disabled")
        ttk.Button(dlg, text="Close", style="Flat.TButton",
                   command=dlg.destroy).pack(pady=(0, 14))

    # ── Clipboard ─────────────────────────────────────────────────────────────

    def _copy_detail(self, var_id: str):
        if var_id == "__all__":
            lines = [f"{k}: {v.get()}" for k, v in self._det.items()]
            text = "\n".join(lines)
        else:
            text = self._det.get(var_id, tk.StringVar()).get()
        if text and text != "—":
            self.clipboard_clear()
            self.clipboard_append(text)
            self._set_status(f"Copied to clipboard.", "ok")

    # ── Export ────────────────────────────────────────────────────────────────

    def _export(self):
        if not self._filtered_devices:
            messagebox.showinfo("Nothing to Export",
                "Run a scan first.", parent=self)
            return
        path = filedialog.asksaveasfilename(
            parent=self, title="Export USB Device Report",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json"), ("Text", "*.txt")])
        if not path:
            return
        try:
            ext = Path(path).suffix.lower()
            if ext == ".json":
                export_json(self._filtered_devices, path)
            elif ext == ".txt":
                export_txt(self._filtered_devices, path)
            else:
                export_csv(self._filtered_devices, path)
            self._set_status(f"✔  Exported {len(self._filtered_devices)} device(s) → {path}", "ok")
            messagebox.showinfo("Export Successful",
                f"Saved {len(self._filtered_devices)} records to:\n{path}", parent=self)
        except Exception as exc:
            messagebox.showerror("Export Failed", str(exc), parent=self)
            self._set_status(f"Export failed: {exc}", "error")

    # ── Status bar ────────────────────────────────────────────────────────────

    def _set_status(self, msg: str, level: str = "info"):
        colours = {"info": CLR_MUTED, "ok": CLR_ACCENT2,
                   "warn": CLR_WARN,  "error": CLR_DANGER}
        self._status_dot.configure(fg=colours.get(level, CLR_MUTED))
        self._status_lbl.configure(text=msg)


# ════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════

def main():
    if sys.platform != "win32":
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Platform Not Supported",
            f"USB RegParse requires Windows (winreg is Windows-only).\n"
            f"Detected platform: {sys.platform}")
        root.destroy()
        sys.exit(1)

    app = USBRegParseApp()
    app.mainloop()


if __name__ == "__main__":
    main()