import ctypes
import concurrent.futures
import csv
import dataclasses
import ipaddress
import json
import os
import queue
import socket
import struct
import subprocess
import sys
import threading
import tkinter as tk
import time
import uuid
import xml.dom.minidom as minidom
import xml.etree.ElementTree as ET
from tkinter import filedialog, messagebox

import customtkinter as ctk

try:
    import paramiko
except ImportError:
    paramiko = None


APP_NAME = "IP Switcher"
ORG_NAME = "Trafsys AS"
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
DWMWA_USE_IMMERSIVE_DARK_MODE = 20
DWMWA_USE_IMMERSIVE_DARK_MODE_OLD = 19
DWMWA_BORDER_COLOR = 34
DWMWA_CAPTION_COLOR = 35
DWMWA_TEXT_COLOR = 36
DARK_BORDER_COLOR = 0x00221B15
DARK_CAPTION_COLOR = 0x00221B15
LIGHT_TEXT_COLOR = 0x00FCFAF7


def app_data_dir():
    if not sys.platform.startswith("win"):
        return os.path.join(os.path.expanduser("~"), APP_NAME)

    root = os.getenv("APPDATA") or os.path.expanduser("~")
    path = os.path.join(root, APP_NAME)
    os.makedirs(path, exist_ok=True)
    return path


APP_DATA_DIR = app_data_dir()
PRESETS_FILE = os.path.join(APP_DATA_DIR, "presets.json")
OLD_AUTOSAVE_FILE = os.path.join(APP_DATA_DIR, "IP Switcher Projects", "autosave.json")
MTPUTTY_PASSWORD_TOKEN = "peziKED81ZUhG8W1I57eIr+AawG6+rvG"
MTPUTTY_COMMAND_OPTIONS = [
    ("Enable", "enable"),
    ("Configure terminal", "conf term"),
    ("Terminal length 0", "terminal length 0"),
    ("Show running config", "show running-config"),
]
PHONE_CONFIG_STATE_FILE = os.path.join(APP_DATA_DIR, "phone-configurator-state.json")
PHONE_CONFIG_LOG_FILE = os.path.join(APP_DATA_DIR, "phone-configurator-log.csv")
PHONE_CONFIG_PENDING_LOG_FILE = os.path.join(APP_DATA_DIR, "phone-configurator-log-pending.csv")
PHONE_CONFIG_SETTINGS_FILE = os.path.join(APP_DATA_DIR, "phone-configurator-settings.json")
PHONE_CONFIG_DEFAULTS = {
    "staging_interface": "",
    "scan_subnet": "10.32.139.0/24",
    "target_start": "10.32.139.175",
    "target_end": "10.32.139.184",
    "netmask": "255.255.255.0",
    "gateway": "10.32.139.254",
    "tftp_server": "10.32.139.150",
    "ssh_username": "root",
    "ssh_password": "n0cerr1er",
    "ssh_port": "22",
    "dhcp_server_ip": "10.32.139.5",
    "dhcp_pool_start": "10.32.139.21",
    "dhcp_pool_end": "10.32.139.50",
    "dhcp_lease_seconds": "600",
    "dhcp_wait_seconds": "180",
    "dhcp_ssh_probe_seconds": "30",
    "ping_timeout_seconds": "180",
    "ping_interval_seconds": "2",
}
PHONE_CONFIG_SETTING_KEYS = list(PHONE_CONFIG_DEFAULTS.keys()) + ["use_dhcp_server"]
PHONE_CONFIG_LOG_FIELDS = [
    "timestamp",
    "mac",
    "dhcp_ip",
    "target_ip",
    "netmask",
    "gateway",
    "tftp_server",
    "status",
    "message",
]


def resource_path(filename):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        os.path.join(base, filename),
        os.path.join(os.path.dirname(os.path.dirname(base)), "etc", filename),
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return candidates[0]


def read_app_version():
    try:
        with open(resource_path("VERSION"), "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return "development"


APP_VERSION = read_app_version()


def apply_dark_window_frame(window):
    if not sys.platform.startswith("win"):
        return

    try:
        window.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        enabled = ctypes.c_int(1)
        for attribute in (DWMWA_USE_IMMERSIVE_DARK_MODE, DWMWA_USE_IMMERSIVE_DARK_MODE_OLD):
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd,
                attribute,
                ctypes.byref(enabled),
                ctypes.sizeof(enabled),
            )

        for attribute, color in (
            (DWMWA_BORDER_COLOR, DARK_BORDER_COLOR),
            (DWMWA_CAPTION_COLOR, DARK_CAPTION_COLOR),
            (DWMWA_TEXT_COLOR, LIGHT_TEXT_COLOR),
        ):
            color_value = ctypes.c_int(color)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd,
                attribute,
                ctypes.byref(color_value),
                ctypes.sizeof(color_value),
            )
    except (AttributeError, OSError, tk.TclError):
        pass


def run_hidden(args, check=False):
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        check=check,
        creationflags=CREATE_NO_WINDOW,
    )


def run_powershell(script):
    return run_hidden(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ]
    )


def prefix_to_subnet_mask(prefix_length):
    if prefix_length in (None, ""):
        return ""

    prefix = int(prefix_length)
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return ".".join(str((mask >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def subnet_mask_to_prefix(mask):
    return ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False).prefixlen


def preset_name(ip, subnet):
    return f"{ip}/{subnet_mask_to_prefix(subnet)}"


def is_bluetooth_interface(interface):
    haystack = f"{interface.get('name', '')} {interface.get('description', '')}".lower()
    return "bluetooth" in haystack


def normalize_preset(preset, fallback_index=None):
    ip = str(preset.get("ip", "")).strip()
    subnet = str(preset.get("subnet", "")).strip()
    gateway = str(preset.get("gateway", "")).strip()

    try:
        name = preset_name(validate_ipv4(ip, "IP address"), validate_subnet_mask(subnet))
    except ValueError:
        name = str(preset.get("name", "")).strip()
        if not name and fallback_index is not None:
            name = f"Preset {fallback_index}"

    return {
        "name": name,
        "ip": ip,
        "subnet": subnet,
        "gateway": gateway,
    }


def normalize_presets(presets):
    return [
        normalize_preset(preset, index)
        for index, preset in enumerate(presets, start=1)
        if isinstance(preset, dict)
    ]


def normalize_json_list(data):
    if not data:
        return []
    if isinstance(data, list):
        return data
    return [data]


def get_interfaces_with_powershell():
    script = r"""
$ErrorActionPreference = 'Stop'
$configs = @{}
Get-NetIPConfiguration | ForEach-Object { $configs[$_.InterfaceAlias] = $_ }
Get-NetAdapter | Sort-Object Name | ForEach-Object {
    $cfg = $configs[$_.Name]
    $ipv4 = if ($cfg -and $cfg.IPv4Address) { $cfg.IPv4Address | Select-Object -First 1 } else { $null }
    $gateway = if ($cfg -and $cfg.IPv4DefaultGateway) { $cfg.IPv4DefaultGateway | Select-Object -First 1 } else { $null }
    [PSCustomObject]@{
        Name = $_.Name
        Description = $_.InterfaceDescription
        Status = $_.Status
        MacAddress = $_.MacAddress
        LinkSpeed = $_.LinkSpeed
        IPv4Address = if ($ipv4) { $ipv4.IPAddress } else { '' }
        PrefixLength = if ($ipv4) { $ipv4.PrefixLength } else { $null }
        Gateway = if ($gateway) { $gateway.NextHop } else { '' }
    }
} | ConvertTo-Json -Depth 3
"""
    result = run_powershell(script)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "PowerShell failed to read adapters.")

    interfaces = [
        {
            "name": item.get("Name", ""),
            "description": item.get("Description", ""),
            "status": item.get("Status", ""),
            "mac": item.get("MacAddress", ""),
            "speed": item.get("LinkSpeed", ""),
            "ip": item.get("IPv4Address", "") or "",
            "subnet": prefix_to_subnet_mask(item.get("PrefixLength")),
            "gateway": item.get("Gateway", "") or "",
        }
        for item in normalize_json_list(json.loads(result.stdout or "[]"))
        if item.get("Name")
    ]
    return [item for item in interfaces if not is_bluetooth_interface(item)]


def get_interfaces_with_ipconfig():
    result = run_hidden(["ipconfig"])
    if result.returncode != 0:
        raise RuntimeError("Failed to retrieve network interfaces.")

    interfaces = []
    current = {}
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if raw_line.startswith(("Ethernet adapter", "Wireless LAN adapter")):
            if current:
                interfaces.append(current)
            name = raw_line.split("adapter", 1)[1].split(":", 1)[0].strip()
            current = {
                "name": name,
                "description": "",
                "status": "",
                "mac": "",
                "speed": "",
                "ip": "",
                "subnet": "",
                "gateway": "",
            }
        elif current and "IPv4 Address" in line:
            current["ip"] = line.split(":", 1)[1].strip()
        elif current and "Subnet Mask" in line:
            current["subnet"] = line.split(":", 1)[1].strip()
        elif current and "Default Gateway" in line:
            current["gateway"] = line.split(":", 1)[1].strip()

    if current:
        interfaces.append(current)
    return [item for item in interfaces if not is_bluetooth_interface(item)]


def get_interfaces():
    try:
        return get_interfaces_with_powershell()
    except Exception:
        return get_interfaces_with_ipconfig()


def validate_ipv4(value, label, allow_empty=False):
    value = value.strip()
    if allow_empty and not value:
        return ""

    try:
        ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be a valid IPv4 address.") from exc
    return value


def validate_subnet_mask(value):
    value = validate_ipv4(value, "Subnet mask")
    try:
        ipaddress.IPv4Network(f"0.0.0.0/{value}", strict=False)
    except ValueError as exc:
        raise ValueError("Subnet mask must be a valid contiguous IPv4 mask.") from exc
    return value


def load_presets():
    if os.path.exists(PRESETS_FILE):
        with open(PRESETS_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        presets = data.get("presets", data if isinstance(data, list) else [])
        return normalize_presets(presets)

    if os.path.exists(OLD_AUTOSAVE_FILE):
        try:
            with open(OLD_AUTOSAVE_FILE, "r", encoding="utf-8") as handle:
                old_data = json.load(handle)
            presets = []
            for index, values in enumerate(old_data.get("ip_configs", []), start=1):
                ip, subnet, gateway = (list(values) + ["", "", ""])[:3]
                if ip or subnet or gateway:
                    presets.append(
                        {
                            "name": f"Imported preset {index}",
                            "ip": ip,
                            "subnet": subnet,
                            "gateway": gateway,
                        }
                    )
            return normalize_presets(presets)
        except (OSError, json.JSONDecodeError, ValueError):
            return []

    return []


def save_presets(presets):
    os.makedirs(APP_DATA_DIR, exist_ok=True)
    with open(PRESETS_FILE, "w", encoding="utf-8") as handle:
        json.dump({"version": APP_VERSION, "presets": normalize_presets(presets)}, handle, indent=2)


def export_presets(path, presets):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"version": APP_VERSION, "presets": normalize_presets(presets)}, handle, indent=2)


def import_presets(path):
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)

    if isinstance(data, dict) and "presets" in data:
        return normalize_presets(data["presets"])
    if isinstance(data, list):
        return normalize_presets(data)
    if isinstance(data, dict) and "ip_configs" in data:
        presets = []
        for index, values in enumerate(data["ip_configs"], start=1):
            ip, subnet, gateway = (list(values) + ["", "", ""])[:3]
            presets.append(
                {
                    "name": f"Imported preset {index}",
                    "ip": ip,
                    "subnet": subnet,
                    "gateway": gateway,
                }
            )
        return normalize_presets(presets)

    raise ValueError("The selected file does not contain IP Switcher presets.")


def parse_multiping_file(file_path):
    entries = []
    with open(file_path, "r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(maxsplit=1)
            ip = validate_ipv4(parts[0], f"Line {line_number} IP address")
            name = parts[1].strip() if len(parts) > 1 else ""
            entries.append({"ip": ip, "name": name})

    if not entries:
        raise ValueError("The selected file does not contain any IP entries.")
    return entries


def mtputty_display_name(entry):
    return f"{entry['ip']} {entry['name']}".strip()


def mtputty_category_name(file_path):
    name = os.path.splitext(os.path.basename(file_path))[0].strip()
    if name.lower().startswith("multiping "):
        name = name[10:].strip()
    return name or "Imported devices"


def add_mtputty_hosts(parent, entries, username, port, commands):
    for entry in entries:
        ip = entry["ip"]
        node = ET.SubElement(parent, "Node", {"Type": "1"})
        ET.SubElement(node, "SavedSession").text = "Default Settings"
        ET.SubElement(node, "DisplayName").text = mtputty_display_name(entry)
        ET.SubElement(node, "UID").text = str(uuid.uuid4())
        ET.SubElement(node, "ServerName").text = ip
        ET.SubElement(node, "PuttyConType").text = "4"
        ET.SubElement(node, "Port").text = str(port)
        ET.SubElement(node, "UserName").text = username
        ET.SubElement(node, "Password").text = MTPUTTY_PASSWORD_TOKEN
        ET.SubElement(node, "PasswordDelay").text = "10"
        ET.SubElement(node, "CLParams").text = f"{ip} -ssh -P {port} -l {username} -pw *****"
        ET.SubElement(node, "ScriptDelay").text = "50"
        script_node = ET.SubElement(node, "Script")
        for index, command in enumerate(commands):
            ET.SubElement(script_node, f"L{index}").text = command


def build_mtputty_tree(entries, folder_name, username, port, commands):
    servers = ET.Element("Servers")
    putty = ET.SubElement(servers, "Putty")
    folder = ET.SubElement(putty, "Node", {"Type": "0", "Expanded": "1"})
    ET.SubElement(folder, "DisplayName").text = folder_name
    add_mtputty_hosts(folder, entries, username, port, commands)
    return servers


def build_mtputty_category_tree(categories, root_folder_name, username, port, commands):
    if not categories:
        raise ValueError("Add at least one multiping text file.")

    servers = ET.Element("Servers")
    putty = ET.SubElement(servers, "Putty")

    for category in categories:
        folder = ET.SubElement(putty, "Node", {"Type": "0", "Expanded": "1"})
        ET.SubElement(folder, "DisplayName").text = category["name"]
        add_mtputty_hosts(folder, category["entries"], username, port, commands)

    return servers


def pretty_xml_bytes(root):
    rough_xml = ET.tostring(root, "utf-8")
    return minidom.parseString(rough_xml).toprettyxml(indent="\t", encoding="UTF-8")


def export_mtputty_xml(input_path, output_path, folder_name, username, port, commands):
    entries = parse_multiping_file(input_path)
    root = build_mtputty_tree(entries, folder_name, username, port, commands)
    with open(output_path, "wb") as handle:
        handle.write(pretty_xml_bytes(root))
    return len(entries)


def export_mtputty_xml_files(input_paths, output_path, root_folder_name, username, port, commands):
    if not input_paths:
        raise ValueError("Add at least one multiping text file.")

    unique_paths = []
    seen = set()
    for path in input_paths:
        normalized = os.path.abspath(path)
        if normalized not in seen:
            seen.add(normalized)
            unique_paths.append(normalized)

    if len(unique_paths) == 1:
        path = unique_paths[0]
        entries = parse_multiping_file(path)
        folder_name = root_folder_name or mtputty_category_name(path)
        root = build_mtputty_tree(entries, folder_name, username, port, commands)
        count = len(entries)
    else:
        categories = []
        count = 0
        for path in unique_paths:
            entries = parse_multiping_file(path)
            categories.append(
                {
                    "name": mtputty_category_name(path),
                    "entries": entries,
                }
            )
            count += len(entries)
        root = build_mtputty_category_tree(
            categories,
            root_folder_name,
            username,
            port,
            commands,
        )

    with open(output_path, "wb") as handle:
        handle.write(pretty_xml_bytes(root))
    return count


@dataclasses.dataclass(frozen=True)
class PhoneConfig:
    staging_interface: str
    scan_subnet: ipaddress.IPv4Network
    target_start: ipaddress.IPv4Address
    target_end: ipaddress.IPv4Address
    netmask: str
    gateway: str
    tftp_server: str
    ssh_username: str
    ssh_password: str
    ssh_port: int
    dhcp_server_ip: ipaddress.IPv4Address
    dhcp_pool_start: ipaddress.IPv4Address
    dhcp_pool_end: ipaddress.IPv4Address
    dhcp_lease_seconds: int
    dhcp_wait_seconds: int
    dhcp_ssh_probe_seconds: int
    ping_timeout_seconds: int
    ping_interval_seconds: int
    use_dhcp_server: bool

    @classmethod
    def from_values(cls, values):
        config = cls(
            staging_interface=values["staging_interface"].strip(),
            scan_subnet=ipaddress.ip_network(values["scan_subnet"].strip(), strict=False),
            target_start=ipaddress.ip_address(values["target_start"].strip()),
            target_end=ipaddress.ip_address(values["target_end"].strip()),
            netmask=validate_subnet_mask(values["netmask"].strip()),
            gateway=validate_ipv4(values["gateway"].strip(), "Gateway"),
            tftp_server=validate_ipv4(values["tftp_server"].strip(), "TFTP server"),
            ssh_username=values["ssh_username"].strip(),
            ssh_password=values["ssh_password"],
            ssh_port=int(values["ssh_port"].strip()),
            dhcp_server_ip=ipaddress.ip_address(values["dhcp_server_ip"].strip()),
            dhcp_pool_start=ipaddress.ip_address(values["dhcp_pool_start"].strip()),
            dhcp_pool_end=ipaddress.ip_address(values["dhcp_pool_end"].strip()),
            dhcp_lease_seconds=int(values["dhcp_lease_seconds"].strip()),
            dhcp_wait_seconds=int(values["dhcp_wait_seconds"].strip()),
            dhcp_ssh_probe_seconds=int(values["dhcp_ssh_probe_seconds"].strip()),
            ping_timeout_seconds=int(values["ping_timeout_seconds"].strip()),
            ping_interval_seconds=int(values["ping_interval_seconds"].strip()),
            use_dhcp_server=bool(values["use_dhcp_server"]),
        )
        config.validate()
        return config

    def validate(self):
        if not self.ssh_username:
            raise ValueError("SSH username is required.")
        if self.use_dhcp_server and not self.staging_interface:
            raise ValueError("Select a network interface for the built-in DHCP server.")
        if not 1 <= self.ssh_port <= 65535:
            raise ValueError("SSH port must be between 1 and 65535.")
        if self.target_start > self.target_end:
            raise ValueError("Target start must be lower than or equal to target end.")
        if self.dhcp_pool_start > self.dhcp_pool_end:
            raise ValueError("DHCP pool start must be lower than or equal to DHCP pool end.")
        if self.dhcp_server_ip not in self.scan_subnet:
            raise ValueError("DHCP server IP must be inside the scan subnet.")
        if self.dhcp_pool_start not in self.scan_subnet or self.dhcp_pool_end not in self.scan_subnet:
            raise ValueError("DHCP pool must be inside the scan subnet.")
        dhcp_values = set(range(int(self.dhcp_pool_start), int(self.dhcp_pool_end) + 1))
        target_values = set(range(int(self.target_start), int(self.target_end) + 1))
        if dhcp_values & target_values:
            raise ValueError("DHCP pool must not overlap the target static IP range.")
        if self.dhcp_lease_seconds < 60:
            raise ValueError("DHCP lease seconds must be at least 60.")
        if self.dhcp_wait_seconds < 10:
            raise ValueError("DHCP wait seconds must be at least 10.")
        if self.dhcp_ssh_probe_seconds < 5:
            raise ValueError("DHCP SSH probe seconds must be at least 5.")
        if self.ping_timeout_seconds < 5:
            raise ValueError("Ping timeout seconds must be at least 5.")
        if self.ping_interval_seconds < 1:
            raise ValueError("Ping interval seconds must be at least 1.")


@dataclasses.dataclass(frozen=True)
class PhoneDhcpLease:
    ip: ipaddress.IPv4Address
    mac: str
    hostname: str
    vendor_class: str


def phone_log(progress, message):
    if progress:
        progress(message)


def phone_load_state():
    if not os.path.exists(PHONE_CONFIG_STATE_FILE):
        return {"phones": []}
    with open(PHONE_CONFIG_STATE_FILE, "r", encoding="utf-8") as handle:
        return json.load(handle)


def phone_save_state(state):
    os.makedirs(APP_DATA_DIR, exist_ok=True)
    with open(PHONE_CONFIG_STATE_FILE, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)


def phone_load_settings():
    settings = dict(PHONE_CONFIG_DEFAULTS)
    settings["use_dhcp_server"] = True
    if os.path.exists(PHONE_CONFIG_SETTINGS_FILE):
        try:
            with open(PHONE_CONFIG_SETTINGS_FILE, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            for key in PHONE_CONFIG_SETTING_KEYS:
                if key in loaded:
                    settings[key] = loaded[key]
        except (OSError, json.JSONDecodeError):
            pass
    return settings


def phone_save_settings(settings):
    os.makedirs(APP_DATA_DIR, exist_ok=True)
    payload = {key: settings[key] for key in PHONE_CONFIG_SETTING_KEYS if key in settings}
    with open(PHONE_CONFIG_SETTINGS_FILE, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)


def phone_append_config_log(record):
    os.makedirs(APP_DATA_DIR, exist_ok=True)
    try:
        return phone_write_config_log_row(PHONE_CONFIG_LOG_FILE, record)
    except OSError:
        return phone_write_config_log_row(PHONE_CONFIG_PENDING_LOG_FILE, record)


def phone_write_config_log_row(path, record):
    file_exists = os.path.exists(path)
    with open(path, "a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=PHONE_CONFIG_LOG_FIELDS)
        if not file_exists:
            writer.writeheader()
        writer.writerow({key: record.get(key, "") for key in PHONE_CONFIG_LOG_FIELDS})
    return path


def phone_ensure_config_log_file():
    if os.path.exists(PHONE_CONFIG_LOG_FILE):
        return
    os.makedirs(APP_DATA_DIR, exist_ok=True)
    with open(PHONE_CONFIG_LOG_FILE, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=PHONE_CONFIG_LOG_FIELDS)
        writer.writeheader()


def phone_read_config_log():
    phone_ensure_config_log_file()
    rows = []
    for path in (PHONE_CONFIG_LOG_FILE, PHONE_CONFIG_PENDING_LOG_FILE):
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", newline="") as handle:
                rows.extend(csv.DictReader(handle))
        except OSError:
            continue
    return rows


def phone_used_target_ips(state):
    return {
        str(phone.get("target_ip"))
        for phone in state.get("phones", [])
        if phone.get("status") in {"pending", "rebooting", "configured"}
    }


def phone_next_target_ip(config, state):
    used = phone_used_target_ips(state)
    for value in range(int(config.target_start), int(config.target_end) + 1):
        candidate = ipaddress.ip_address(value)
        if str(candidate) not in used:
            return candidate
    raise RuntimeError("No free target IPs remain in the configured range.")


def phone_append_assignment(state, dhcp_ip, target_ip, status, dhcp_mac=None, message=None):
    item = {
        "dhcp_ip": str(dhcp_ip),
        "target_ip": str(target_ip),
        "status": status,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    if dhcp_mac:
        item["dhcp_mac"] = dhcp_mac
    if message:
        item["message"] = message
    state.setdefault("phones", []).append(item)


def phone_update_assignment(state, target_ip, status, message=None):
    target = str(target_ip)
    for phone in reversed(state.get("phones", [])):
        if phone.get("target_ip") == target:
            phone["status"] = status
            phone["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            if message:
                phone["message"] = message
            return


def phone_ip_to_bytes(value):
    return socket.inet_aton(str(value))


def phone_bytes_to_ip(value):
    return ipaddress.ip_address(socket.inet_ntoa(value))


def phone_mac_to_text(value):
    return ":".join(f"{byte:02x}" for byte in value)


def phone_parse_dhcp_options(data):
    options = {}
    index = 0
    while index < len(data):
        code = data[index]
        index += 1
        if code == 255:
            break
        if code == 0:
            continue
        if index >= len(data):
            break
        length = data[index]
        index += 1
        options[code] = data[index : index + length]
        index += length
    return options


def phone_dhcp_option(code, value):
    if len(value) > 255:
        raise ValueError(f"DHCP option {code} is too long.")
    return bytes([code, len(value)]) + value


def phone_dhcp_message_type(options):
    value = options.get(53)
    return value[0] if value else None


def phone_build_dhcp_discover(transaction_id):
    chaddr = b"\x02\x49\x50\x53\x57\x01" + b"\x00" * 10
    fixed = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1,
        1,
        6,
        0,
        transaction_id,
        0,
        0x8000,
        b"\x00\x00\x00\x00",
        b"\x00\x00\x00\x00",
        b"\x00\x00\x00\x00",
        b"\x00\x00\x00\x00",
        chaddr,
        b"",
        b"",
    )
    options = [
        phone_dhcp_option(53, b"\x01"),
        phone_dhcp_option(55, bytes([1, 3, 6, 28, 51, 54])),
        phone_dhcp_option(12, b"IP-Switcher-Probe"),
        b"\xff",
    ]
    return fixed + b"\x63\x82\x53\x63" + b"".join(options)


def phone_probe_other_dhcp_servers(config, progress=None, timeout_seconds=4):
    if not config.use_dhcp_server:
        return []

    transaction_id = int(time.time() * 1000) & 0xFFFFFFFF
    discover = phone_build_dhcp_discover(transaction_id)
    offers = []
    phone_log(progress, f"Checking for other DHCP servers on {config.staging_interface}...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.bind(("", 68))
            sock.settimeout(0.5)
            sock.sendto(discover, ("255.255.255.255", 67))
            sock.sendto(discover, (str(config.scan_subnet.broadcast_address), 67))
            deadline = time.monotonic() + timeout_seconds
            while time.monotonic() < deadline:
                try:
                    data, _addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                if len(data) < 240 or data[236:240] != b"\x63\x82\x53\x63":
                    continue
                _op, _htype, _hlen, _hops, xid, _secs, _flags = struct.unpack("!BBBBIHH", data[:12])
                if xid != transaction_id:
                    continue
                options = phone_parse_dhcp_options(data[240:])
                if phone_dhcp_message_type(options) != 2:
                    continue
                server_id = options.get(54)
                server_ip = phone_bytes_to_ip(server_id) if server_id and len(server_id) == 4 else "unknown"
                offered_ip = phone_bytes_to_ip(data[16:20])
                if str(server_ip) == str(config.dhcp_server_ip):
                    continue
                offers.append({"server": str(server_ip), "offered_ip": str(offered_ip)})
    except PermissionError as exc:
        raise RuntimeError("DHCP conflict check needs Administrator privileges to bind UDP port 68.") from exc
    except OSError as exc:
        raise RuntimeError(f"DHCP conflict check could not run: {exc}") from exc

    unique = []
    seen = set()
    for offer in offers:
        key = (offer["server"], offer["offered_ip"])
        if key not in seen:
            seen.add(key)
            unique.append(offer)
    if unique:
        for offer in unique:
            phone_log(progress, f"Detected other DHCP server {offer['server']} offering {offer['offered_ip']}.")
    else:
        phone_log(progress, "No other DHCP server responded to the probe.")
    return unique


class PhoneDhcpServer:
    def __init__(self, config, progress=None):
        self.config = config
        self.progress = progress
        self.thread = None
        self.stop_event = threading.Event()
        self.ready_event = threading.Event()
        self.start_error = None
        self.leases = {}
        self.lease_queue = queue.Queue()
        self.socket = None

    def start(self):
        if self.thread:
            return
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()
        if not self.ready_event.wait(timeout=5):
            raise RuntimeError("DHCP server did not finish starting within 5 seconds.")
        if self.start_error:
            raise RuntimeError(self.start_error)

    def stop(self):
        self.stop_event.set()
        if self.socket:
            try:
                self.socket.close()
            except OSError:
                pass
        if self.thread:
            self.thread.join(timeout=2)

    def wait_for_lease(self, timeout_seconds):
        try:
            return self.lease_queue.get(timeout=timeout_seconds)
        except queue.Empty as exc:
            raise TimeoutError("Timed out waiting for a DHCP lease.") from exc

    def serve(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                self.socket = sock
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.bind(("", 67))
                sock.settimeout(1)
                self.ready_event.set()
                phone_log(
                    self.progress,
                    f"DHCP server listening on UDP/67 using {self.config.dhcp_server_ip} "
                    f"as server IP with pool {self.config.dhcp_pool_start}-{self.config.dhcp_pool_end}",
                )
                while not self.stop_event.is_set():
                    try:
                        data, _addr = sock.recvfrom(4096)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    try:
                        self.handle_packet(sock, data)
                    except Exception as exc:
                        phone_log(self.progress, f"DHCP warning: {exc}")
        except PermissionError:
            self.start_error = "DHCP server needs Administrator privileges to bind UDP port 67."
            self.ready_event.set()
        except OSError as exc:
            self.start_error = f"DHCP server could not start: {exc}"
            self.ready_event.set()

    def handle_packet(self, sock, data):
        if len(data) < 240 or data[236:240] != b"\x63\x82\x53\x63":
            return

        fixed = data[:236]
        op, _htype, hlen, _hops, xid, _secs, flags = struct.unpack("!BBBBIHH", fixed[:12])
        if op != 1 or hlen < 1:
            return

        ciaddr = fixed[12:16]
        chaddr = fixed[28 : 28 + hlen]
        mac = phone_mac_to_text(chaddr[:6])
        options = phone_parse_dhcp_options(data[240:])
        msg_type = phone_dhcp_message_type(options)
        if msg_type not in {1, 3}:
            return

        hostname = options.get(12, b"").decode(errors="ignore")
        vendor_class = options.get(60, b"").decode(errors="ignore")
        if msg_type == 1:
            offered_ip = self.lease_for_mac(mac)
            phone_log(self.progress, f"DHCP discover from {mac}; offering {offered_ip}")
            reply_type = 2
        else:
            server_identifier = options.get(54)
            if server_identifier and server_identifier != phone_ip_to_bytes(self.config.dhcp_server_ip):
                selected_server = phone_bytes_to_ip(server_identifier) if len(server_identifier) == 4 else "unknown"
                phone_log(self.progress, f"Ignoring DHCP request from {mac}; selected server is {selected_server}")
                return
            if mac not in self.leases:
                phone_log(self.progress, f"Ignoring DHCP request from {mac}; no offer was made to this MAC")
                return
            offered_ip = self.leases[mac]
            requested_ip = self.requested_ip(options, ciaddr)
            if requested_ip and requested_ip != offered_ip:
                phone_log(self.progress, f"Ignoring DHCP request from {mac}; requested {requested_ip}, offered {offered_ip}")
                return
            phone_log(self.progress, f"DHCP request from {mac}; ack {offered_ip}")
            reply_type = 5
            self.lease_queue.put(PhoneDhcpLease(offered_ip, mac, hostname, vendor_class))

        reply = self.build_reply(fixed, xid, flags, fixed[28:44], offered_ip, reply_type)
        sock.sendto(reply, ("255.255.255.255", 68))
        sock.sendto(reply, (str(self.config.scan_subnet.broadcast_address), 68))

    def lease_for_mac(self, mac):
        if mac in self.leases:
            return self.leases[mac]
        used = set(self.leases.values())
        for value in range(int(self.config.dhcp_pool_start), int(self.config.dhcp_pool_end) + 1):
            candidate = ipaddress.ip_address(value)
            if candidate not in used:
                self.leases[mac] = candidate
                return candidate
        raise RuntimeError("No free DHCP lease IPs remain.")

    def requested_ip(self, options, ciaddr):
        requested = options.get(50)
        if requested and len(requested) == 4:
            return phone_bytes_to_ip(requested)
        if ciaddr != b"\x00\x00\x00\x00":
            return phone_bytes_to_ip(ciaddr)
        return None

    def build_reply(self, _request, xid, flags, chaddr, yiaddr, message_type):
        fixed = struct.pack(
            "!BBBBIHH4s4s4s4s16s64s128s",
            2,
            1,
            6,
            0,
            xid,
            0,
            flags,
            b"\x00\x00\x00\x00",
            phone_ip_to_bytes(yiaddr),
            phone_ip_to_bytes(self.config.dhcp_server_ip),
            b"\x00\x00\x00\x00",
            chaddr,
            b"",
            b"",
        )
        options = [
            phone_dhcp_option(53, bytes([message_type])),
            phone_dhcp_option(54, phone_ip_to_bytes(self.config.dhcp_server_ip)),
            phone_dhcp_option(51, struct.pack("!I", self.config.dhcp_lease_seconds)),
            phone_dhcp_option(1, phone_ip_to_bytes(self.config.netmask)),
            phone_dhcp_option(3, phone_ip_to_bytes(self.config.gateway)),
            phone_dhcp_option(6, phone_ip_to_bytes(self.config.gateway)),
            phone_dhcp_option(28, phone_ip_to_bytes(self.config.scan_subnet.broadcast_address)),
            phone_dhcp_option(66, self.config.tftp_server.encode()),
            b"\xff",
        ]
        return fixed + b"\x63\x82\x53\x63" + b"".join(options)


def phone_tcp_port_open(host, port, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((str(host), port)) == 0


def phone_ssh_connect(host, config):
    if paramiko is None:
        raise RuntimeError("Missing dependency: install paramiko.")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=str(host),
        port=config.ssh_port,
        username=config.ssh_username,
        password=config.ssh_password,
        look_for_keys=False,
        allow_agent=False,
        timeout=3,
        auth_timeout=3,
        banner_timeout=3,
    )
    return client


def phone_wait_for_ssh_login(host, config, timeout_seconds, progress=None):
    deadline = time.monotonic() + timeout_seconds
    last_error = ""
    phone_log(progress, f"Waiting for SSH login on {host}...")
    while time.monotonic() < deadline:
        try:
            client = phone_ssh_connect(host, config)
            client.close()
            phone_log(progress, f"SSH login OK: {host}")
            return
        except Exception as exc:
            last_error = str(exc)
            time.sleep(2)
    raise TimeoutError(f"Timed out waiting for SSH login on {host}: {last_error}")


def phone_find_with_dhcp_server(config, progress=None):
    server = PhoneDhcpServer(config, progress=progress)
    server.start()
    try:
        phone_log(progress, "Waiting for a DHCP phone lease...")
        deadline = time.monotonic() + config.dhcp_wait_seconds
        last_error = ""
        while time.monotonic() < deadline:
            remaining = max(1, int(deadline - time.monotonic()))
            lease = server.wait_for_lease(remaining)
            phone_log(progress, f"DHCP lease: {lease.ip} for {lease.mac}")
            if lease.hostname:
                phone_log(progress, f"Hostname: {lease.hostname}")
            if lease.vendor_class:
                phone_log(progress, f"Vendor class: {lease.vendor_class}")
            try:
                phone_wait_for_ssh_login(lease.ip, config, config.dhcp_ssh_probe_seconds, progress)
                return lease
            except TimeoutError as exc:
                last_error = str(exc)
                phone_log(progress, f"Lease {lease.ip} did not accept phone SSH login; still waiting.")
        raise TimeoutError(f"Timed out waiting for a DHCP lease with phone SSH login: {last_error}")
    finally:
        server.stop()


def phone_find_by_scan(config, progress=None):
    hosts = [str(host) for host in config.scan_subnet.hosts()]
    phone_log(progress, f"Scanning {config.scan_subnet} for SSH on port {config.ssh_port}...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
        futures = {
            pool.submit(phone_tcp_port_open, host, config.ssh_port, 1.5): host
            for host in hosts
        }
        candidates = []
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            try:
                if future.result():
                    candidates.append(host)
                    phone_log(progress, f"SSH open: {host}")
            except OSError:
                pass

    authenticated = []
    for candidate in sorted(candidates, key=ipaddress.ip_address):
        try:
            client = phone_ssh_connect(candidate, config)
            client.close()
            authenticated.append(candidate)
            phone_log(progress, f"Phone login OK: {candidate}")
        except Exception as exc:
            phone_log(progress, f"Skipping {candidate}: {exc}")

    if not authenticated:
        raise RuntimeError("No scanned SSH hosts accepted the phone login.")
    if len(authenticated) > 1:
        raise RuntimeError("More than one device accepted the phone login. Use DHCP mode or isolate one phone.")
    return PhoneDhcpLease(ipaddress.ip_address(authenticated[0]), "", "", "")


def phone_interfaces_content(target_ip, config):
    return "\n".join(
        [
            "# Configure Loopback",
            "auto lo",
            "iface lo inet loopback",
            "",
            "auto eth0",
            "iface eth0 inet static",
            f"address {target_ip}",
            f"netmask {config.netmask}",
            f"gateway {config.gateway}",
            f"server  {config.tftp_server}",
            "",
        ]
    )


def phone_sh_single_quote(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def phone_run_ssh_command(client, command, timeout=30):
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    exit_code = stdout.channel.recv_exit_status()
    return exit_code, stdout.read().decode(errors="replace"), stderr.read().decode(errors="replace")


def phone_write_config(dhcp_ip, target_ip, config, progress=None):
    content = phone_interfaces_content(target_ip, config)
    tftp_content = config.tftp_server + "\n"
    backup_suffix = time.strftime("%Y%m%d-%H%M%S")
    command = "\n".join(
        [
            "set -e",
            f"cp /etc/network/interfaces /etc/network/interfaces.bak-ip-switcher-{backup_suffix}",
            f"cp /etc/tftp_server /etc/tftp_server.bak-ip-switcher-{backup_suffix}",
            f"printf %s {phone_sh_single_quote(content)} > /etc/network/interfaces",
            f"printf %s {phone_sh_single_quote(tftp_content)} > /etc/tftp_server",
            "sync",
            "(sleep 1; reboot) >/dev/null 2>&1 &",
        ]
    )
    phone_log(progress, f"Connecting to {dhcp_ip} over SSH...")
    client = phone_ssh_connect(dhcp_ip, config)
    try:
        phone_log(progress, f"Writing static IP {target_ip} and TFTP server {config.tftp_server}...")
        exit_code, stdout_text, stderr_text = phone_run_ssh_command(client, command, timeout=30)
        if exit_code != 0:
            raise RuntimeError(
                f"Remote configuration failed with exit code {exit_code}\n"
                f"stdout: {stdout_text}\n"
                f"stderr: {stderr_text}"
            )
    finally:
        client.close()


def phone_read_remote_mac(host, config):
    client = phone_ssh_connect(host, config)
    try:
        exit_code, stdout_text, _stderr_text = phone_run_ssh_command(
            client,
            "cat /sys/class/net/eth0/address 2>/dev/null || true",
            timeout=10,
        )
    finally:
        client.close()
    if exit_code != 0:
        return ""
    return stdout_text.strip().lower()


def phone_interface_has_ip(interface_name, ip_address):
    escaped_name = interface_name.replace("'", "''")
    escaped_ip = str(ip_address).replace("'", "''")
    script = f"""
$ErrorActionPreference = 'Stop'
$match = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias '{escaped_name}' -ErrorAction SilentlyContinue |
    Where-Object {{ $_.IPAddress -eq '{escaped_ip}' }} |
    Select-Object -First 1
if ($match) {{ 'true' }} else {{ 'false' }}
"""
    result = run_powershell(script)
    return result.returncode == 0 and result.stdout.strip().lower() == "true"


def phone_wait_for_interface_ip(config, progress=None, timeout_seconds=20):
    deadline = time.monotonic() + timeout_seconds
    phone_log(progress, f"Waiting for Windows to apply {config.dhcp_server_ip} on {config.staging_interface}...")
    while time.monotonic() < deadline:
        if phone_interface_has_ip(config.staging_interface, config.dhcp_server_ip):
            phone_log(progress, f"Confirmed {config.staging_interface} has {config.dhcp_server_ip}.")
            return
        time.sleep(1)
    raise RuntimeError(
        f"{config.staging_interface} did not show {config.dhcp_server_ip} within {timeout_seconds} seconds."
    )


def phone_apply_staging_interface(config, progress=None):
    if not config.use_dhcp_server:
        return

    args = [
        "netsh",
        "interface",
        "ipv4",
        "set",
        "address",
        f"name={config.staging_interface}",
        "source=static",
        f"address={config.dhcp_server_ip}",
        f"mask={config.netmask}",
        f"gateway={config.gateway or 'none'}",
    ]
    phone_log(progress, f"Setting {config.staging_interface} to {config.dhcp_server_ip}/{config.netmask}...")
    result = run_hidden(args)
    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or result.stdout.strip()
            or f"Could not set {config.staging_interface} to {config.dhcp_server_ip}."
        )
    phone_wait_for_interface_ip(config, progress)
    phone_log(progress, f"{config.staging_interface} is ready for DHCP hosting.")


def phone_ping_once(host):
    command = ["ping", "-n", "1", "-w", "1000", str(host)]
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
    return result.returncode == 0


def phone_wait_for_ping(host, timeout_seconds, interval_seconds, progress=None):
    deadline = time.monotonic() + timeout_seconds
    success_count = 0
    phone_log(progress, f"Waiting for ping replies from {host}...")
    while time.monotonic() < deadline:
        if phone_ping_once(host):
            success_count += 1
            phone_log(progress, f"Ping reply {success_count}/3")
            if success_count >= 3:
                return True
        else:
            success_count = 0
        time.sleep(interval_seconds)
    return False


def phone_normalize_remote_text(value):
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in value.strip().split("\n"))


def phone_verify_settings(host, target_ip, config):
    expected_interfaces = phone_normalize_remote_text(phone_interfaces_content(target_ip, config))
    expected_tftp = phone_normalize_remote_text(config.tftp_server)
    marker = "---IP-SWITCHER-TFTP---"
    command = f"cat /etc/network/interfaces; printf '\\n{marker}\\n'; cat /etc/tftp_server"
    client = phone_ssh_connect(host, config)
    try:
        exit_code, stdout_text, stderr_text = phone_run_ssh_command(client, command, timeout=15)
    finally:
        client.close()
    if exit_code != 0:
        return False, f"Could not read remote config: {stderr_text.strip()}"
    if marker not in stdout_text:
        return False, "Could not parse remote config output."
    interfaces_text, tftp_text = stdout_text.split(marker, 1)
    if phone_normalize_remote_text(interfaces_text) != expected_interfaces:
        return False, "Remote /etc/network/interfaces does not match expected static config."
    if phone_normalize_remote_text(tftp_text) != expected_tftp:
        return False, "Remote /etc/tftp_server does not match expected TFTP server."
    return True, "Ping and SSH file verification succeeded."


def phone_wait_for_settings_verification(host, target_ip, config, progress=None):
    deadline = time.monotonic() + config.ping_timeout_seconds
    last_message = ""
    phone_log(progress, f"Verifying actual settings over SSH on {host}...")
    while time.monotonic() < deadline:
        try:
            verified, message = phone_verify_settings(host, target_ip, config)
            if verified:
                phone_log(progress, "SSH settings verification OK.")
                return True, message
            last_message = message
        except Exception as exc:
            last_message = str(exc)
        time.sleep(config.ping_interval_seconds)
    return False, last_message or "SSH settings verification timed out."


def phone_configure_next(config, progress=None):
    state = phone_load_state()
    target_ip = phone_next_target_ip(config, state)
    phone_apply_staging_interface(config, progress)
    conflicting_servers = phone_probe_other_dhcp_servers(config, progress)
    if conflicting_servers:
        details = "\n".join(
            f"Server {item['server']} offered {item['offered_ip']}"
            for item in conflicting_servers
        )
        raise RuntimeError(
            "Another DHCP server was detected on the selected interface.\n"
            f"{details}\n"
            "The built-in DHCP server was not started. Use an isolated switch/VLAN/direct cable, "
            "or disable the other DHCP server for the provisioning port."
        )
    lease = phone_find_with_dhcp_server(config, progress) if config.use_dhcp_server else phone_find_by_scan(config, progress)
    phone_log(progress, f"Planned assignment: DHCP {lease.ip} -> static {target_ip}")
    phone_mac = lease.mac
    if not phone_mac:
        try:
            phone_mac = phone_read_remote_mac(lease.ip, config)
            if phone_mac:
                phone_log(progress, f"Phone MAC: {phone_mac}")
        except Exception as exc:
            phone_log(progress, f"Could not read phone MAC before configuration: {exc}")
    log_base = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "mac": phone_mac,
        "dhcp_ip": str(lease.ip),
        "target_ip": str(target_ip),
        "netmask": config.netmask,
        "gateway": config.gateway,
        "tftp_server": config.tftp_server,
    }

    phone_append_assignment(state, lease.ip, target_ip, "pending", dhcp_mac=phone_mac)
    phone_save_state(state)
    try:
        phone_write_config(lease.ip, target_ip, config, progress)
        phone_update_assignment(state, target_ip, "rebooting")
        phone_save_state(state)

        if not phone_wait_for_ping(target_ip, config.ping_timeout_seconds, config.ping_interval_seconds, progress):
            phone_update_assignment(state, target_ip, "failed", "Timed out waiting for ping.")
            phone_save_state(state)
            raise RuntimeError(f"{target_ip} did not respond to ping before timeout.")

        verified, message = phone_wait_for_settings_verification(target_ip, target_ip, config, progress)
        if not verified:
            phone_update_assignment(state, target_ip, "failed", message)
            phone_save_state(state)
            raise RuntimeError(message)

        phone_update_assignment(state, target_ip, "configured", message)
        phone_save_state(state)
        try:
            log_path = phone_append_config_log({**log_base, "status": "configured", "message": message})
            if log_path != PHONE_CONFIG_LOG_FILE:
                phone_log(progress, f"Main CSV log was locked; wrote assignment to {os.path.basename(log_path)}.")
        except OSError as log_exc:
            phone_log(progress, f"Could not write phone assignment log: {log_exc}")
        phone_log(progress, f"Success: {target_ip} is responding and settings were verified.")
        return target_ip
    except Exception as exc:
        phone_update_assignment(state, target_ip, "failed", str(exc))
        phone_save_state(state)
        try:
            log_path = phone_append_config_log({**log_base, "status": "failed", "message": str(exc)})
            if log_path != PHONE_CONFIG_LOG_FILE:
                phone_log(progress, f"Main CSV log was locked; wrote assignment to {os.path.basename(log_path)}.")
        except OSError as log_exc:
            phone_log(progress, f"Could not write phone assignment log: {log_exc}")
        raise


class IPSwitcherApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION}")
        self.geometry("1040x760")
        self.minsize(940, 700)

        self.interfaces = []
        self.interface_buttons = {}
        self.selected_interface = None
        self.presets = load_presets()

        self.ip_var = tk.StringVar()
        self.subnet_var = tk.StringVar(value="255.255.255.0")
        self.gateway_var = tk.StringVar()
        self.preset_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        self.mtputty_window = None
        self.phone_config_window = None

        self.current_values = {}

        self.configure(fg_color="#101418")
        self.set_icon()
        self.build_menu()
        self.build_layout()
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.after(50, lambda: apply_dark_window_frame(self))

        self.update_preset_menu()
        self.after(100, self.refresh_interfaces)

    def set_icon(self):
        try:
            self.iconbitmap(resource_path("icon3.ico"))
        except tk.TclError:
            pass

    def build_menu(self):
        self.menu_items = {
            "File": [
                ("Import presets...", self.import_presets_from_file),
                ("Export presets...", self.export_presets_to_file),
                None,
                ("Exit", self.close),
            ],
            "Tools": [
                ("MTPuTTY XML generator...", self.open_mtputty_generator),
                ("Phone configurator...", self.open_phone_configurator),
            ],
            "Help": [
                ("About", self.show_about),
            ],
        }

    def build_header_menu(self, parent):
        for column, (label, items) in enumerate(self.menu_items.items()):
            button = ctk.CTkButton(
                parent,
                text=label,
                width=74,
                height=34,
                fg_color="#182029",
                hover_color="#2f3b46",
                text_color="#d8e0e7",
                border_width=1,
                border_color="#34414d",
            )
            button.grid(row=0, column=column, padx=(0, 8))
            button.configure(command=lambda target=button, menu_items=items: self.show_popup_menu(target, menu_items))

    def show_popup_menu(self, anchor, items):
        menu = tk.Menu(
            self,
            tearoff=False,
            bg="#182029",
            fg="#f7fafc",
            activebackground="#1f6f8b",
            activeforeground="#ffffff",
            disabledforeground="#6f7e8c",
            borderwidth=0,
            relief="flat",
        )
        for item in items:
            if item is None:
                menu.add_separator()
                continue
            label, command = item
            menu.add_command(label=label, command=command)

        try:
            menu.tk_popup(anchor.winfo_rootx(), anchor.winfo_rooty() + anchor.winfo_height() + 4)
        finally:
            menu.grab_release()

    def raise_dialog(self, window):
        try:
            window.lift()
            window.focus_force()
            window.attributes("-topmost", True)
            window.after(250, lambda: window.attributes("-topmost", False) if window.winfo_exists() else None)
        except tk.TclError:
            pass

    def build_layout(self):
        self.grid_columnconfigure(0, minsize=305)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="#151b22", corner_radius=0)
        header.grid(row=0, column=0, columnspan=2, sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        header.grid_columnconfigure(1, weight=0)
        header.grid_columnconfigure(2, weight=0)

        title_block = ctk.CTkFrame(header, fg_color="transparent")
        title_block.grid(row=0, column=0, sticky="w", padx=22, pady=16)
        ctk.CTkLabel(
            title_block,
            text=APP_NAME,
            font=ctk.CTkFont(size=26, weight="bold"),
            text_color="#f7fafc",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            title_block,
            text="Network interface IP configuration",
            font=ctk.CTkFont(size=13),
            text_color="#9aa8b6",
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        menu_frame = ctk.CTkFrame(header, fg_color="transparent")
        menu_frame.grid(row=0, column=1, padx=(12, 0), pady=16)
        self.build_header_menu(menu_frame)

        ctk.CTkButton(
            header,
            text="Refresh",
            width=110,
            command=self.refresh_interfaces,
            fg_color="#1f6f8b",
            hover_color="#2382a4",
        ).grid(row=0, column=2, padx=22, pady=16)

        sidebar = ctk.CTkFrame(self, fg_color="#151b22", corner_radius=0)
        sidebar.grid(row=1, column=0, sticky="nsew")
        sidebar.grid_rowconfigure(1, weight=1)
        sidebar.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            sidebar,
            text="Interfaces",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#f7fafc",
        ).grid(row=0, column=0, sticky="w", padx=18, pady=(18, 8))

        self.interface_list = ctk.CTkScrollableFrame(
            sidebar,
            fg_color="transparent",
            scrollbar_button_color="#2f3b46",
            scrollbar_button_hover_color="#3b4a57",
        )
        self.interface_list.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 14))
        self.interface_list.grid_columnconfigure(0, weight=1)

        main = ctk.CTkFrame(self, fg_color="#101418", corner_radius=0)
        main.grid(row=1, column=1, sticky="nsew", padx=22, pady=18)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(3, weight=1, minsize=14)

        self.current_panel = ctk.CTkFrame(main, fg_color="#182029", corner_radius=8)
        self.current_panel.grid(row=0, column=0, sticky="ew")
        self.current_panel.grid_columnconfigure((1, 3), weight=1)
        self.build_current_panel()

        form_panel = ctk.CTkFrame(main, fg_color="#182029", corner_radius=8)
        form_panel.grid(row=1, column=0, sticky="ew", pady=(16, 0))
        form_panel.grid_columnconfigure((0, 1, 2), weight=1)
        self.build_form_panel(form_panel)

        preset_panel = ctk.CTkFrame(main, fg_color="#182029", corner_radius=8)
        preset_panel.grid(row=2, column=0, sticky="ew", pady=(16, 0))
        preset_panel.grid_columnconfigure(0, weight=1)
        self.build_preset_panel(preset_panel)

        status_bar = ctk.CTkFrame(main, fg_color="#151b22", corner_radius=8)
        status_bar.grid(row=4, column=0, sticky="ew", pady=(12, 0))
        status_bar.grid_columnconfigure(0, weight=1)

        self.status_label = ctk.CTkLabel(
            status_bar,
            textvariable=self.status_var,
            anchor="w",
            text_color="#9aa8b6",
        )
        self.status_label.grid(row=0, column=0, sticky="ew", padx=12, pady=8)

    def build_current_panel(self):
        ctk.CTkLabel(
            self.current_panel,
            text="Current Configuration",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#f7fafc",
        ).grid(row=0, column=0, columnspan=4, sticky="w", padx=18, pady=(16, 10))

        labels = [
            ("Interface", "interface"),
            ("Status", "status"),
            ("IPv4", "ip"),
            ("Subnet", "subnet"),
            ("Gateway", "gateway"),
            ("Speed", "speed"),
        ]
        for index, (label, key) in enumerate(labels, start=1):
            row = (index + 1) // 2
            label_col = 0 if index % 2 else 2
            value_col = label_col + 1
            ctk.CTkLabel(
                self.current_panel,
                text=label,
                text_color="#9aa8b6",
                anchor="w",
            ).grid(row=row, column=label_col, sticky="w", padx=(18, 8), pady=6)
            value = ctk.CTkLabel(
                self.current_panel,
                text="-",
                text_color="#f7fafc",
                anchor="w",
            )
            value.grid(row=row, column=value_col, sticky="ew", padx=(0, 18), pady=6)
            self.current_values[key] = value

    def build_form_panel(self, panel):
        ctk.CTkLabel(
            panel,
            text="Static IP",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#f7fafc",
        ).grid(row=0, column=0, columnspan=3, sticky="w", padx=18, pady=(16, 10))

        self.ip_entry = self.entry_group(panel, "IP address", self.ip_var, 1, 0)
        self.subnet_entry = self.entry_group(panel, "Subnet mask", self.subnet_var, 1, 1)
        self.gateway_entry = self.entry_group(panel, "Gateway", self.gateway_var, 1, 2)

        actions = ctk.CTkFrame(panel, fg_color="transparent")
        actions.grid(row=3, column=0, columnspan=3, sticky="ew", padx=18, pady=(14, 18))
        actions.grid_columnconfigure((0, 1, 2, 3), weight=1)

        ctk.CTkButton(
            actions,
            text="Apply Static IP",
            command=self.apply_static_ip,
            fg_color="#2d8a66",
            hover_color="#35a579",
        ).grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ctk.CTkButton(
            actions,
            text="Enable DHCP",
            command=self.enable_dhcp,
            fg_color="#1f6f8b",
            hover_color="#2382a4",
        ).grid(row=0, column=1, sticky="ew", padx=8)
        ctk.CTkButton(
            actions,
            text="Use Current",
            command=self.fill_from_current,
            fg_color="#2f3b46",
            hover_color="#3b4a57",
        ).grid(row=0, column=2, sticky="ew", padx=8)
        ctk.CTkButton(
            actions,
            text="Clear",
            command=self.clear_form,
            fg_color="#2f3b46",
            hover_color="#3b4a57",
        ).grid(row=0, column=3, sticky="ew", padx=(8, 0))

    def entry_group(self, parent, label, variable, row, column):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=row, column=column, sticky="ew", padx=18, pady=(0, 4))
        frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(frame, text=label, text_color="#9aa8b6").grid(row=0, column=0, sticky="w")
        entry = ctk.CTkEntry(
            frame,
            textvariable=variable,
            height=38,
            border_width=1,
            border_color="#34414d",
            fg_color="#101418",
        )
        entry.grid(row=1, column=0, sticky="ew", pady=(5, 0))
        return entry

    def build_preset_panel(self, panel):
        ctk.CTkLabel(
            panel,
            text="Presets",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#f7fafc",
        ).grid(row=0, column=0, sticky="w", padx=18, pady=(16, 10))

        controls = ctk.CTkFrame(panel, fg_color="transparent")
        controls.grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 18))
        controls.grid_columnconfigure(0, weight=1)

        self.preset_menu = ctk.CTkOptionMenu(
            controls,
            variable=self.preset_var,
            values=["No presets saved"],
            command=lambda _: self.fill_from_selected_preset(),
            fg_color="#101418",
            button_color="#2f3b46",
            button_hover_color="#3b4a57",
        )
        self.preset_menu.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        buttons = [
            ("Load", self.fill_from_selected_preset, "#2f3b46", "#3b4a57"),
            ("Apply", self.apply_selected_preset, "#2d8a66", "#35a579"),
            ("Save", self.save_current_as_preset, "#1f6f8b", "#2382a4"),
            ("Delete", self.delete_selected_preset, "#70363b", "#8a4248"),
        ]
        for index, (text, command, color, hover) in enumerate(buttons, start=1):
            ctk.CTkButton(
                controls,
                text=text,
                width=86,
                command=command,
                fg_color=color,
                hover_color=hover,
            ).grid(row=0, column=index, padx=(0, 8 if index < len(buttons) else 0))

    def open_mtputty_generator(self):
        if self.mtputty_window and self.mtputty_window.winfo_exists():
            self.mtputty_window.focus()
            return

        window = ctk.CTkToplevel(self)
        self.mtputty_window = window
        window.title("MTPuTTY XML Generator")
        window.geometry("820x820")
        window.minsize(740, 720)
        window.transient(self)
        window.configure(fg_color="#101418")
        window.grid_columnconfigure(0, weight=1)
        window.grid_rowconfigure(2, weight=1, minsize=210)
        window.grid_rowconfigure(4, weight=2, minsize=300)
        window.after(50, lambda: apply_dark_window_frame(window))

        selected_files = []
        username_var = tk.StringVar(value="admin")
        port_var = tk.StringVar(value="22")
        status_var = tk.StringVar(value="Add one or more multiping text files.")
        command_vars = {}

        ctk.CTkLabel(
            window,
            text="MTPuTTY XML Generator",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#f7fafc",
        ).grid(row=0, column=0, sticky="w", padx=20, pady=(18, 4))

        ctk.CTkLabel(
            window,
            text="Build an importable MTPuTTY tree from one file, many files, or a folder of ring files.",
            text_color="#9aa8b6",
            anchor="w",
        ).grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 14))

        file_panel = ctk.CTkFrame(window, fg_color="#182029", corner_radius=8)
        file_panel.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 12))
        file_panel.grid_columnconfigure(0, weight=1)
        file_panel.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(
            file_panel,
            text="Multiping sources",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color="#f7fafc",
        ).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 0))
        ctk.CTkLabel(
            file_panel,
            text="Each selected file becomes a category folder in the exported tree.",
            text_color="#9aa8b6",
        ).grid(row=1, column=0, sticky="w", padx=14, pady=(2, 8))

        file_actions = ctk.CTkFrame(file_panel, fg_color="transparent")
        file_actions.grid(row=0, column=1, rowspan=2, sticky="e", padx=14, pady=(12, 8))

        file_list = ctk.CTkScrollableFrame(
            file_panel,
            height=130,
            fg_color="#101418",
            corner_radius=8,
            border_width=1,
            border_color="#34414d",
        )
        file_list.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=14, pady=(0, 14))
        file_list.grid_columnconfigure(0, weight=1)

        def remove_file(index):
            if 0 <= index < len(selected_files):
                selected_files.pop(index)
            update_file_list()
            summarize_files()

        def update_file_list():
            for child in file_list.winfo_children():
                child.destroy()

            if not selected_files:
                ctk.CTkLabel(
                    file_list,
                    text="No files added yet.",
                    text_color="#6f7e8c",
                    anchor="w",
                ).grid(row=0, column=0, sticky="ew", padx=12, pady=12)
                return

            for index, item in enumerate(selected_files):
                row = ctk.CTkFrame(file_list, fg_color="#182029", corner_radius=6)
                row.grid(row=index, column=0, sticky="ew", padx=8, pady=(8, 0))
                row.grid_columnconfigure(0, weight=1)
                ctk.CTkLabel(
                    row,
                    text=f"{item['category']} ({item['count']} hosts)",
                    text_color="#f7fafc",
                    anchor="w",
                    font=ctk.CTkFont(size=13, weight="bold"),
                ).grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 0))
                ctk.CTkLabel(
                    row,
                    text=item["path"],
                    text_color="#9aa8b6",
                    anchor="w",
                    wraplength=520,
                ).grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 8))
                ctk.CTkButton(
                    row,
                    text="Remove",
                    width=76,
                    height=28,
                    command=lambda remove_index=index: remove_file(remove_index),
                    fg_color="#70363b",
                    hover_color="#8a4248",
                ).grid(row=0, column=1, rowspan=2, padx=10, pady=8)

        def summarize_files():
            total_hosts = sum(item["count"] for item in selected_files)
            if not selected_files:
                status_var.set("Add one or more multiping text files.")
            elif len(selected_files) == 1:
                status_var.set(f"Ready: 1 category with {total_hosts} host(s).")
            else:
                status_var.set(f"Ready: {len(selected_files)} categories with {total_hosts} host(s).")

        def add_multiping_paths(paths):
            added = 0
            errors = []
            existing = {item["path"].lower() for item in selected_files}
            for path in paths:
                if not path:
                    continue
                normalized = os.path.abspath(path)
                if normalized.lower() in existing:
                    continue
                try:
                    entries = parse_multiping_file(normalized)
                except (OSError, ValueError) as exc:
                    errors.append(f"{os.path.basename(path)}: {exc}")
                    continue

                selected_files.append(
                    {
                        "path": normalized,
                        "category": mtputty_category_name(normalized),
                        "count": len(entries),
                    }
                )
                existing.add(normalized.lower())
                added += 1

            update_file_list()
            summarize_files()
            if errors:
                messagebox.showwarning("Some Files Were Skipped", "\n".join(errors[:8]), parent=window)

        def browse_multiping_files():
            paths = filedialog.askopenfilenames(
                title="Open multiping files",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                initialdir=APP_DATA_DIR,
            )
            add_multiping_paths(paths)

        def browse_multiping_folder():
            folder = filedialog.askdirectory(
                title="Open folder with multiping files",
                initialdir=APP_DATA_DIR,
            )
            if not folder:
                return
            paths = [
                os.path.join(folder, name)
                for name in sorted(os.listdir(folder))
                if name.lower().endswith(".txt")
            ]
            if not paths:
                messagebox.showerror("No Text Files", "The selected folder does not contain any .txt files.", parent=window)
                return
            add_multiping_paths(paths)

        def clear_files():
            selected_files.clear()
            update_file_list()
            summarize_files()

        ctk.CTkButton(
            file_actions,
            text="Add files",
            width=96,
            command=browse_multiping_files,
            fg_color="#1f6f8b",
            hover_color="#2382a4",
        ).grid(row=0, column=0, padx=(0, 8))
        ctk.CTkButton(
            file_actions,
            text="Add folder",
            width=104,
            command=browse_multiping_folder,
            fg_color="#1f6f8b",
            hover_color="#2382a4",
        ).grid(row=0, column=1, padx=(0, 8))
        ctk.CTkButton(
            file_actions,
            text="Clear",
            width=72,
            command=clear_files,
            fg_color="#2f3b46",
            hover_color="#3b4a57",
        ).grid(row=0, column=2)
        update_file_list()

        config_panel = ctk.CTkFrame(window, fg_color="#182029", corner_radius=8)
        config_panel.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 12))
        config_panel.grid_columnconfigure((0, 1), weight=1)

        username_entry = self.dialog_entry_group(config_panel, "Username", username_var, 0, 0)
        port_entry = self.dialog_entry_group(config_panel, "SSH port", port_var, 0, 1)
        for entry in (username_entry, port_entry):
            entry.configure(height=36)

        command_panel = ctk.CTkFrame(window, fg_color="#182029", corner_radius=8)
        command_panel.grid(row=4, column=0, sticky="nsew", padx=20, pady=(0, 12))
        command_panel.grid_columnconfigure(0, weight=1)
        window.grid_rowconfigure(4, weight=1)

        ctk.CTkLabel(
            command_panel,
            text="Login commands",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color="#f7fafc",
        ).grid(row=0, column=0, sticky="w", padx=14, pady=(14, 8))

        for index, (label, command) in enumerate(MTPUTTY_COMMAND_OPTIONS, start=1):
            var = tk.BooleanVar(value=command in {"enable", "conf term"})
            command_vars[command] = var
            ctk.CTkCheckBox(
                command_panel,
                text=f"{label}  ({command})",
                variable=var,
                text_color="#d8e0e7",
                fg_color="#1f6f8b",
                hover_color="#2382a4",
            ).grid(row=index, column=0, sticky="w", padx=14, pady=3)

        ctk.CTkLabel(command_panel, text="Custom commands", text_color="#9aa8b6").grid(
            row=5, column=0, sticky="w", padx=14, pady=(12, 0)
        )
        custom_text = ctk.CTkTextbox(
            command_panel,
            height=150,
            fg_color="#101418",
            border_width=1,
            border_color="#34414d",
        )
        custom_text.grid(row=6, column=0, sticky="nsew", padx=14, pady=(6, 14))
        command_panel.grid_rowconfigure(6, weight=1)

        footer = ctk.CTkFrame(window, fg_color="transparent")
        footer.grid(row=5, column=0, sticky="ew", padx=20, pady=(0, 16))
        footer.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(footer, textvariable=status_var, text_color="#9aa8b6", anchor="w").grid(
            row=0, column=0, sticky="ew", padx=(0, 12)
        )

        def selected_commands():
            commands = [
                command
                for _label, command in MTPUTTY_COMMAND_OPTIONS
                if command_vars[command].get()
            ]
            custom_commands = [
                line.strip()
                for line in custom_text.get("1.0", "end").splitlines()
                if line.strip()
            ]
            return commands + custom_commands

        def generate_xml_file():
            if not selected_files:
                messagebox.showerror("Missing Files", "Add at least one multiping text file.", parent=window)
                return

            username = username_var.get().strip()
            if not username:
                messagebox.showerror("Missing Username", "Enter an SSH username.", parent=window)
                return

            try:
                port = int(port_var.get().strip())
                if port < 1 or port > 65535:
                    raise ValueError
            except ValueError:
                messagebox.showerror("Invalid Port", "Enter a valid TCP port from 1 to 65535.", parent=window)
                return

            output_path = filedialog.asksaveasfilename(
                title="Save MTPuTTY XML",
                defaultextension=".xml",
                filetypes=[("XML files", "*.xml"), ("All files", "*.*")],
                initialdir=os.path.dirname(selected_files[0]["path"]),
                initialfile=f"{selected_files[0]['category'] if len(selected_files) == 1 else 'MTPuTTY'}.xml",
            )
            if not output_path:
                return

            try:
                count = export_mtputty_xml_files(
                    [item["path"] for item in selected_files],
                    output_path,
                    selected_files[0]["category"] if len(selected_files) == 1 else "",
                    username,
                    port,
                    selected_commands(),
                )
            except (OSError, ValueError) as exc:
                messagebox.showerror("Export Failed", str(exc), parent=window)
                return

            category_text = "category" if len(selected_files) == 1 else "categories"
            status_var.set(f"Exported {count} host(s) across {len(selected_files)} {category_text}.")
            messagebox.showinfo("Export Complete", f"Created MTPuTTY XML for {count} host(s).", parent=window)

        ctk.CTkButton(
            footer,
            text="Generate XML",
            width=140,
            command=generate_xml_file,
            fg_color="#2d8a66",
            hover_color="#35a579",
        ).grid(row=0, column=1, sticky="e")

    def open_phone_configurator(self):
        if self.phone_config_window and self.phone_config_window.winfo_exists():
            self.raise_dialog(self.phone_config_window)
            return

        window = ctk.CTkToplevel(self)
        self.phone_config_window = window
        window.title("Phone Configurator")
        window.geometry("1120x760")
        window.minsize(980, 680)
        window.configure(fg_color="#101418")
        window.grid_columnconfigure(0, weight=1)
        window.grid_rowconfigure(1, weight=1)
        window.transient(self)
        window.protocol("WM_DELETE_WINDOW", window.destroy)
        window.after(50, lambda: apply_dark_window_frame(window))
        window.after(100, lambda: self.raise_dialog(window))

        saved_settings = phone_load_settings()
        values = {
            key: tk.StringVar(value=str(saved_settings.get(key, PHONE_CONFIG_DEFAULTS[key])))
            for key in PHONE_CONFIG_DEFAULTS
        }
        phone_interfaces = []
        staging_interface_var = values["staging_interface"]
        use_dhcp_var = tk.BooleanVar(value=bool(saved_settings.get("use_dhcp_server", True)))
        status_var = tk.StringVar(value="Ready to configure one phone.")
        log_queue = queue.Queue()
        worker_state = {"running": False}
        log_text = None
        start_button = None

        header = ctk.CTkFrame(window, fg_color="#151b22", corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            header,
            text="Phone Configurator",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#f7fafc",
        ).grid(row=0, column=0, sticky="w", padx=20, pady=(14, 0))
        ctk.CTkLabel(
            header,
            text="DHCP staging, SSH static IP setup, ping, and read-back verification",
            text_color="#9aa8b6",
        ).grid(row=1, column=0, sticky="w", padx=20, pady=(2, 14))

        content = ctk.CTkFrame(window, fg_color="transparent")
        content.grid(row=1, column=0, sticky="nsew", padx=20, pady=(18, 12))
        footer = ctk.CTkFrame(window, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 16))

        def clear_frame(frame):
            for child in frame.winfo_children():
                child.destroy()
            for index in range(8):
                frame.grid_columnconfigure(index, weight=0, minsize=0)
                frame.grid_rowconfigure(index, weight=0, minsize=0)

        def append_log(message):
            if not log_text or not log_text.winfo_exists():
                return
            log_text.insert("end", f"{time.strftime('%H:%M:%S')}  {message}\n")
            log_text.see("end")

        def read_phone_values():
            raw = {key: variable.get() for key, variable in values.items()}
            raw["use_dhcp_server"] = use_dhcp_var.get()
            return PhoneConfig.from_values(raw)

        def settings_payload():
            payload = {key: variable.get() for key, variable in values.items()}
            payload["use_dhcp_server"] = use_dhcp_var.get()
            return payload

        def refresh_phone_interfaces():
            nonlocal phone_interfaces
            try:
                phone_interfaces = get_interfaces()
            except Exception:
                phone_interfaces = []
            names = [item["name"] for item in phone_interfaces]
            if names and staging_interface_var.get() not in names:
                selected = self.selected_interface if self.selected_interface in names else ""
                if not selected:
                    active = next((item["name"] for item in phone_interfaces if item.get("status") == "Up"), "")
                    selected = active or names[0]
                staging_interface_var.set(selected)
            return names

        def load_saved_settings_into_form():
            settings = phone_load_settings()
            for key, variable in values.items():
                variable.set(str(settings.get(key, PHONE_CONFIG_DEFAULTS[key])))
            use_dhcp_var.set(bool(settings.get("use_dhcp_server", True)))

        def show_assignment_log():
            rows = phone_read_config_log()
            log_window = ctk.CTkToplevel(window)
            log_window.title("Phone Configuration Log")
            log_window.geometry("980x560")
            log_window.minsize(860, 460)
            log_window.configure(fg_color="#101418")
            log_window.grid_columnconfigure(0, weight=1)
            log_window.grid_rowconfigure(1, weight=1)
            log_window.transient(window)
            log_window.after(50, lambda: apply_dark_window_frame(log_window))
            log_window.after(100, lambda: self.raise_dialog(log_window))

            ctk.CTkLabel(
                log_window,
                text="Phone Configuration Log",
                font=ctk.CTkFont(size=20, weight="bold"),
                text_color="#f7fafc",
            ).grid(row=0, column=0, sticky="w", padx=20, pady=(18, 8))

            text = ctk.CTkTextbox(
                log_window,
                fg_color="#101418",
                border_width=1,
                border_color="#34414d",
                text_color="#d8e0e7",
                font=ctk.CTkFont(family="Consolas", size=12),
            )
            text.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 14))

            if rows:
                header_line = (
                    f"{'Timestamp':<20} {'MAC':<17} {'DHCP IP':<15} {'Target IP':<15} "
                    f"{'Gateway':<15} {'TFTP':<15} {'Status':<12} Message\n"
                )
                text.insert("end", header_line)
                text.insert("end", "-" * 140 + "\n")
                for row in rows:
                    text.insert(
                        "end",
                        f"{row.get('timestamp', ''):<20} "
                        f"{row.get('mac', ''):<17} "
                        f"{row.get('dhcp_ip', ''):<15} "
                        f"{row.get('target_ip', ''):<15} "
                        f"{row.get('gateway', ''):<15} "
                        f"{row.get('tftp_server', ''):<15} "
                        f"{row.get('status', ''):<12} "
                        f"{row.get('message', '')}\n",
                    )
            else:
                text.insert("end", "No phone configuration entries have been recorded yet.\n")

            actions = ctk.CTkFrame(log_window, fg_color="transparent")
            actions.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 16))
            actions.grid_columnconfigure(0, weight=1)
            log_paths_text = PHONE_CONFIG_LOG_FILE
            if os.path.exists(PHONE_CONFIG_PENDING_LOG_FILE):
                log_paths_text = f"{PHONE_CONFIG_LOG_FILE} + {os.path.basename(PHONE_CONFIG_PENDING_LOG_FILE)}"
            ctk.CTkLabel(actions, text=log_paths_text, text_color="#9aa8b6", anchor="w").grid(
                row=0, column=0, sticky="ew", padx=(0, 12)
            )
            ctk.CTkButton(
                actions,
                text="Open CSV",
                width=96,
                command=open_assignment_log_file,
                fg_color="#1f6f8b",
                hover_color="#2382a4",
            ).grid(row=0, column=1, padx=(0, 8))
            ctk.CTkButton(
                actions,
                text="Close",
                width=80,
                command=log_window.destroy,
                fg_color="#2f3b46",
                hover_color="#3b4a57",
            ).grid(row=0, column=2)

        def open_assignment_log_file():
            phone_ensure_config_log_file()
            try:
                os.startfile(PHONE_CONFIG_LOG_FILE)
            except OSError as exc:
                messagebox.showerror("Open Log Failed", str(exc), parent=window)

        def open_assignment_log_folder():
            phone_ensure_config_log_file()
            try:
                os.startfile(APP_DATA_DIR)
            except OSError as exc:
                messagebox.showerror("Open Folder Failed", str(exc), parent=window)

        def poll_log_queue():
            nonlocal start_button
            while True:
                try:
                    kind, message = log_queue.get_nowait()
                except queue.Empty:
                    break
                if kind == "log":
                    append_log(message)
                elif kind == "status":
                    status_var.set(message)
                elif kind == "done":
                    worker_state["running"] = False
                    if start_button and start_button.winfo_exists():
                        start_button.configure(state="normal")
                    status_var.set(message)
                    show_run_view()
                elif kind == "error":
                    worker_state["running"] = False
                    if start_button and start_button.winfo_exists():
                        start_button.configure(state="normal")
                    status_var.set("Configuration failed.")
                    messagebox.showerror("Phone Configuration Failed", message, parent=window)
            if window.winfo_exists():
                window.after(200, poll_log_queue)

        def run_worker(config):
            try:
                result_ip = phone_configure_next(config, progress=lambda message: log_queue.put(("log", message)))
            except Exception as exc:
                log_queue.put(("log", f"ERROR: {exc}"))
                log_queue.put(("error", str(exc)))
                return
            log_queue.put(("done", f"Configured and verified {result_ip}."))

        def start_configuration():
            if worker_state["running"]:
                return
            try:
                config = read_phone_values()
            except Exception as exc:
                messagebox.showerror("Invalid Phone Configuration", str(exc), parent=window)
                return
            phone_save_settings(settings_payload())
            if config.use_dhcp_server and not messagebox.askyesno(
                "Start DHCP Server",
                "Start the built-in DHCP server on UDP port 67?\n\nUse this only on an isolated provisioning network.",
                parent=window,
            ):
                return

            log_text.delete("1.0", "end")
            append_log("Starting phone configuration.")
            status_var.set("Configuring phone...")
            worker_state["running"] = True
            if start_button and start_button.winfo_exists():
                start_button.configure(state="disabled")
            threading.Thread(target=run_worker, args=(config,), daemon=True).start()

        def summary_label(parent, title, value, row):
            ctk.CTkLabel(parent, text=title, text_color="#9aa8b6", anchor="w").grid(
                row=row, column=0, sticky="w", padx=14, pady=5
            )
            ctk.CTkLabel(parent, text=value, text_color="#f7fafc", anchor="w").grid(
                row=row, column=1, sticky="ew", padx=(0, 14), pady=5
            )

        def render_recent_log(parent):
            rows = phone_read_config_log()[-8:]
            text = ctk.CTkTextbox(
                parent,
                height=170,
                fg_color="#101418",
                border_width=1,
                border_color="#34414d",
                text_color="#d8e0e7",
                font=ctk.CTkFont(family="Consolas", size=12),
            )
            text.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))
            if not rows:
                text.insert("end", "No phones configured yet.\n")
                return
            for row in rows:
                text.insert(
                    "end",
                    f"{row.get('target_ip', '-'):<15} {row.get('mac', '-'):<17} "
                    f"{row.get('status', '-'):<12} {row.get('message', '')}\n",
                )

        def show_run_view(refresh_only=False):
            nonlocal log_text, start_button
            if not refresh_only:
                clear_frame(content)
                clear_frame(footer)
                content.grid_columnconfigure(0, minsize=360)
                content.grid_columnconfigure(1, weight=1)
                content.grid_rowconfigure(0, weight=1)

                left = ctk.CTkFrame(content, fg_color="transparent")
                left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
                left.grid_columnconfigure(0, weight=1)
                right = ctk.CTkFrame(content, fg_color="#182029", corner_radius=8)
                right.grid(row=0, column=1, sticky="nsew")
                right.grid_columnconfigure(0, weight=1)
                right.grid_rowconfigure(1, weight=1)
            else:
                left = content.grid_slaves(row=0, column=0)[0]
                for child in left.winfo_children():
                    child.destroy()
                right = content.grid_slaves(row=0, column=1)[0]

            summary_panel = ctk.CTkFrame(left, fg_color="#182029", corner_radius=8)
            summary_panel.grid(row=0, column=0, sticky="ew", pady=(0, 12))
            summary_panel.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(
                summary_panel,
                text="Current Plan",
                font=ctk.CTkFont(size=15, weight="bold"),
                text_color="#f7fafc",
            ).grid(row=0, column=0, columnspan=2, sticky="w", padx=14, pady=(14, 8))
            try:
                config = read_phone_values()
                next_ip = phone_next_target_ip(config, phone_load_state())
                summary_label(summary_panel, "Next IP", str(next_ip), 1)
                summary_label(summary_panel, "Target range", f"{config.target_start} - {config.target_end}", 2)
                summary_label(
                    summary_panel,
                    "DHCP staging",
                    f"{config.dhcp_pool_start} - {config.dhcp_pool_end} via {config.dhcp_server_ip}"
                    if config.use_dhcp_server
                    else "SSH scan mode",
                    3,
                )
                summary_label(summary_panel, "Interface", config.staging_interface or "-", 4)
                summary_label(summary_panel, "Gateway", config.gateway, 5)
                summary_label(summary_panel, "TFTP", config.tftp_server, 6)
            except Exception as exc:
                summary_label(summary_panel, "Settings", f"Invalid: {exc}", 1)

            recent_panel = ctk.CTkFrame(left, fg_color="#182029", corner_radius=8)
            recent_panel.grid(row=1, column=0, sticky="nsew")
            recent_panel.grid_columnconfigure(0, weight=1)
            recent_panel.grid_rowconfigure(1, weight=1)
            left.grid_rowconfigure(1, weight=1)
            ctk.CTkLabel(
                recent_panel,
                text="Last Configured Phones",
                font=ctk.CTkFont(size=15, weight="bold"),
                text_color="#f7fafc",
            ).grid(row=0, column=0, sticky="w", padx=14, pady=(14, 8))
            render_recent_log(recent_panel)

            if not refresh_only:
                ctk.CTkLabel(
                    right,
                    text="Live Run Log",
                    font=ctk.CTkFont(size=15, weight="bold"),
                    text_color="#f7fafc",
                ).grid(row=0, column=0, sticky="w", padx=14, pady=(14, 8))
                log_text = ctk.CTkTextbox(
                    right,
                    fg_color="#101418",
                    border_width=1,
                    border_color="#34414d",
                    text_color="#d8e0e7",
                )
                log_text.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))

                footer.grid_columnconfigure(0, weight=1)
                ctk.CTkLabel(footer, textvariable=status_var, text_color="#9aa8b6", anchor="w").grid(
                    row=0, column=0, sticky="ew", padx=(0, 12)
                )
                ctk.CTkButton(
                    footer,
                    text="Settings",
                    width=96,
                    command=show_settings_view,
                    fg_color="#1f6f8b",
                    hover_color="#2382a4",
                ).grid(row=0, column=1, padx=(0, 8))
                ctk.CTkButton(
                    footer,
                    text="View Log",
                    width=92,
                    command=show_assignment_log,
                    fg_color="#1f6f8b",
                    hover_color="#2382a4",
                ).grid(row=0, column=2, padx=(0, 8))
                ctk.CTkButton(
                    footer,
                    text="Open CSV",
                    width=92,
                    command=open_assignment_log_file,
                    fg_color="#1f6f8b",
                    hover_color="#2382a4",
                ).grid(row=0, column=3, padx=(0, 8))
                ctk.CTkButton(
                    footer,
                    text="Folder",
                    width=78,
                    command=open_assignment_log_folder,
                    fg_color="#2f3b46",
                    hover_color="#3b4a57",
                ).grid(row=0, column=4, padx=(0, 8))
                ctk.CTkButton(
                    footer,
                    text="Clear Log",
                    width=96,
                    command=lambda: log_text.delete("1.0", "end") if log_text else None,
                    fg_color="#2f3b46",
                    hover_color="#3b4a57",
                ).grid(row=0, column=5, padx=(0, 8))
                start_button = ctk.CTkButton(
                    footer,
                    text="Configure Next Phone",
                    width=180,
                    command=start_configuration,
                    fg_color="#2d8a66",
                    hover_color="#35a579",
                )
                start_button.grid(row=0, column=6)
                if worker_state["running"]:
                    start_button.configure(state="disabled")

        def add_settings_panel(parent, title, row):
            panel = ctk.CTkFrame(parent, fg_color="#182029", corner_radius=8)
            panel.grid(row=row, column=0, sticky="ew", pady=(0, 12))
            panel.grid_columnconfigure((0, 1, 2), weight=1)
            ctk.CTkLabel(
                panel,
                text=title,
                font=ctk.CTkFont(size=15, weight="bold"),
                text_color="#f7fafc",
            ).grid(row=0, column=0, columnspan=3, sticky="w", padx=14, pady=(14, 0))
            return panel

        def save_settings_from_view():
            try:
                read_phone_values()
            except Exception as exc:
                messagebox.showerror("Invalid Phone Configuration", str(exc), parent=window)
                return
            phone_save_settings(settings_payload())
            status_var.set("Phone configurator settings saved.")
            show_run_view()

        def cancel_settings_view():
            load_saved_settings_into_form()
            status_var.set("Settings changes discarded.")
            show_run_view()

        def show_settings_view():
            clear_frame(content)
            clear_frame(footer)
            content.grid_columnconfigure(0, weight=1)
            content.grid_rowconfigure(0, weight=1)
            settings_scroll = ctk.CTkScrollableFrame(
                content,
                fg_color="transparent",
                scrollbar_button_color="#2f3b46",
                scrollbar_button_hover_color="#3b4a57",
            )
            settings_scroll.grid(row=0, column=0, sticky="nsew")
            settings_scroll.grid_columnconfigure(0, weight=1)

            network_panel = add_settings_panel(settings_scroll, "Static Phone Network", 0)
            self.dialog_entry_group(network_panel, "Scan subnet", values["scan_subnet"], 1, 0)
            self.dialog_entry_group(network_panel, "Target start", values["target_start"], 1, 1)
            self.dialog_entry_group(network_panel, "Target end", values["target_end"], 1, 2)
            self.dialog_entry_group(network_panel, "Netmask", values["netmask"], 2, 0)
            self.dialog_entry_group(network_panel, "Gateway", values["gateway"], 2, 1)
            self.dialog_entry_group(network_panel, "TFTP server", values["tftp_server"], 2, 2)

            dhcp_panel = add_settings_panel(settings_scroll, "DHCP Staging", 1)
            interface_names = refresh_phone_interfaces()
            ctk.CTkCheckBox(
                dhcp_panel,
                text="Run built-in DHCP server",
                variable=use_dhcp_var,
                text_color="#d8e0e7",
                fg_color="#1f6f8b",
                hover_color="#2382a4",
            ).grid(row=1, column=0, sticky="w", padx=14, pady=14)
            ctk.CTkLabel(dhcp_panel, text="Host interface", text_color="#9aa8b6").grid(
                row=1, column=1, sticky="w", padx=14, pady=(14, 0)
            )
            interface_menu = ctk.CTkOptionMenu(
                dhcp_panel,
                variable=staging_interface_var,
                values=interface_names or ["No interfaces found"],
                fg_color="#101418",
                button_color="#1f6f8b",
                button_hover_color="#2382a4",
                dropdown_fg_color="#182029",
                dropdown_hover_color="#1f6f8b",
                state="normal" if interface_names else "disabled",
            )
            interface_menu.grid(row=2, column=1, sticky="ew", padx=14, pady=(5, 14))
            def refresh_interface_menu():
                names = refresh_phone_interfaces()
                interface_menu.configure(
                    values=names or ["No interfaces found"],
                    state="normal" if names else "disabled",
                )
            ctk.CTkButton(
                dhcp_panel,
                text="Refresh Interfaces",
                width=136,
                command=refresh_interface_menu,
                fg_color="#2f3b46",
                hover_color="#3b4a57",
            ).grid(row=2, column=2, sticky="w", padx=14, pady=(5, 14))
            self.dialog_entry_group(dhcp_panel, "Interface IP to set", values["dhcp_server_ip"], 3, 0)
            self.dialog_entry_group(dhcp_panel, "DHCP pool start", values["dhcp_pool_start"], 3, 1)
            self.dialog_entry_group(dhcp_panel, "DHCP pool end", values["dhcp_pool_end"], 3, 2)
            self.dialog_entry_group(dhcp_panel, "Lease seconds", values["dhcp_lease_seconds"], 4, 0)
            self.dialog_entry_group(dhcp_panel, "DHCP wait", values["dhcp_wait_seconds"], 4, 1)

            ssh_panel = add_settings_panel(settings_scroll, "SSH", 2)
            self.dialog_entry_group(ssh_panel, "Username", values["ssh_username"], 1, 0)
            self.dialog_entry_group(ssh_panel, "SSH port", values["ssh_port"], 1, 1)
            self.dialog_entry_group(ssh_panel, "SSH probe seconds", values["dhcp_ssh_probe_seconds"], 1, 2)
            password_entry = self.dialog_entry_group(ssh_panel, "Password", values["ssh_password"], 2, 0)
            password_entry.configure(show="*")

            verify_panel = add_settings_panel(settings_scroll, "Verification", 3)
            self.dialog_entry_group(verify_panel, "Ping timeout", values["ping_timeout_seconds"], 1, 0)
            self.dialog_entry_group(verify_panel, "Ping interval", values["ping_interval_seconds"], 1, 1)

            footer.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(footer, textvariable=status_var, text_color="#9aa8b6", anchor="w").grid(
                row=0, column=0, sticky="ew", padx=(0, 12)
            )
            ctk.CTkButton(
                footer,
                text="Cancel",
                width=86,
                command=cancel_settings_view,
                fg_color="#2f3b46",
                hover_color="#3b4a57",
            ).grid(row=0, column=1, padx=(0, 8))
            ctk.CTkButton(
                footer,
                text="Save Settings",
                width=128,
                command=save_settings_from_view,
                fg_color="#2d8a66",
                hover_color="#35a579",
            ).grid(row=0, column=2)

        show_run_view()
        poll_log_queue()

    def dialog_entry_group(self, parent, label, variable, row, column):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=row, column=column, sticky="ew", padx=14, pady=14)
        frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(frame, text=label, text_color="#9aa8b6").grid(row=0, column=0, sticky="w")
        entry = ctk.CTkEntry(
            frame,
            textvariable=variable,
            border_width=1,
            border_color="#34414d",
            fg_color="#101418",
        )
        entry.grid(row=1, column=0, sticky="ew", pady=(5, 0))
        return entry

    def refresh_interfaces(self):
        if not sys.platform.startswith("win"):
            messagebox.showerror("Unsupported OS", "IP Switcher can only change IP settings on Windows.")
            return

        self.set_status("Refreshing interfaces...")
        try:
            self.interfaces = get_interfaces()
        except Exception as exc:
            messagebox.showerror("Interface Error", str(exc))
            self.set_status("Could not read network interfaces.")
            return

        self.render_interfaces()
        if self.interfaces:
            preferred = self.selected_interface or self.interfaces[0]["name"]
            if preferred not in {item["name"] for item in self.interfaces}:
                preferred = self.interfaces[0]["name"]
            self.select_interface(preferred)
            self.set_status(f"Found {len(self.interfaces)} network interface(s).")
        else:
            self.select_interface(None)
            self.set_status("No network interfaces found.")

    def render_interfaces(self):
        for child in self.interface_list.winfo_children():
            child.destroy()
        self.interface_buttons.clear()

        for row, interface in enumerate(self.interfaces):
            name = interface["name"]
            status = interface.get("status") or "Unknown"
            ip = interface.get("ip") or "No IPv4 address"

            row_frame = ctk.CTkFrame(
                self.interface_list,
                fg_color="#1c252e",
                corner_radius=8,
                border_width=1,
                border_color="#25313b",
            )
            row_frame.grid(row=row, column=0, sticky="ew", padx=6, pady=5)
            row_frame.grid_columnconfigure(0, weight=1)
            row_frame.grid_columnconfigure(1, minsize=108)

            name_label = ctk.CTkLabel(
                row_frame,
                text=self.short_text(name, 28),
                anchor="w",
                justify="left",
                text_color="#f7fafc",
                font=ctk.CTkFont(size=13, weight="bold"),
            )
            name_label.grid(row=0, column=0, sticky="ew", padx=(12, 8), pady=(9, 0))

            ip_label = ctk.CTkLabel(
                row_frame,
                text=ip,
                anchor="e",
                justify="right",
                text_color="#d8e0e7",
                font=ctk.CTkFont(size=12),
            )
            ip_label.grid(row=0, column=1, sticky="e", padx=(4, 12), pady=(9, 0))

            detail = interface.get("description") or interface.get("speed") or ""
            detail_label = ctk.CTkLabel(
                row_frame,
                text=self.short_text(detail, 34),
                anchor="w",
                justify="left",
                text_color="#8fa0af",
                font=ctk.CTkFont(size=11),
            )
            detail_label.grid(row=1, column=0, sticky="ew", padx=(12, 8), pady=(0, 9))

            status_label = ctk.CTkLabel(
                row_frame,
                text=status,
                anchor="e",
                justify="right",
                text_color="#8fa0af",
                font=ctk.CTkFont(size=11),
            )
            status_label.grid(row=1, column=1, sticky="e", padx=(4, 12), pady=(0, 9))

            self.bind_interface_row(row_frame, name)
            for widget in (name_label, ip_label, detail_label, status_label):
                self.bind_interface_row(widget, name)

            self.interface_buttons[name] = {
                "frame": row_frame,
                "labels": (name_label, ip_label, detail_label, status_label),
            }

    def short_text(self, text, limit):
        if not text or len(text) <= limit:
            return text
        return f"{text[:limit - 3]}..."

    def bind_interface_row(self, widget, name):
        widget.bind("<Button-1>", lambda _event, value=name: self.select_interface(value))
        widget.bind("<Enter>", lambda _event, value=name: self.set_interface_hover(value, True))
        widget.bind("<Leave>", lambda _event, value=name: self.set_interface_hover(value, False))

    def set_interface_hover(self, name, is_hovered):
        row = self.interface_buttons.get(name)
        if not row or name == self.selected_interface:
            return
        row["frame"].configure(fg_color="#26323d" if is_hovered else "#1c252e")

    def select_interface(self, name):
        self.selected_interface = name
        interface = self.get_selected_interface()

        for button_name, row in self.interface_buttons.items():
            is_selected = button_name == name
            row["frame"].configure(
                fg_color="#1f6f8b" if is_selected else "#1c252e",
                border_color="#44a3c7" if is_selected else "#25313b",
            )
            primary, ip_label, detail, status = row["labels"]
            primary.configure(text_color="#ffffff")
            ip_label.configure(text_color="#ffffff" if is_selected else "#d8e0e7")
            detail.configure(text_color="#c8d7e0" if is_selected else "#8fa0af")
            status.configure(text_color="#c8d7e0" if is_selected else "#8fa0af")

        values = {
            "interface": "-",
            "status": "-",
            "ip": "-",
            "subnet": "-",
            "gateway": "-",
            "speed": "-",
        }
        if interface:
            values.update(
                {
                    "interface": interface["name"],
                    "status": interface.get("status") or "-",
                    "ip": interface.get("ip") or "-",
                    "subnet": interface.get("subnet") or "-",
                    "gateway": interface.get("gateway") or "-",
                    "speed": interface.get("speed") or "-",
                }
            )

        for key, label in self.current_values.items():
            label.configure(text=values[key])

    def get_selected_interface(self):
        if not self.selected_interface:
            return None
        return next(
            (item for item in self.interfaces if item["name"] == self.selected_interface),
            None,
        )

    def read_form(self):
        ip = validate_ipv4(self.ip_var.get(), "IP address")
        subnet = validate_subnet_mask(self.subnet_var.get())
        gateway = validate_ipv4(self.gateway_var.get(), "Gateway", allow_empty=True)
        return ip, subnet, gateway

    def apply_static_ip(self):
        interface = self.get_selected_interface()
        if not interface:
            messagebox.showerror("No Interface", "Select a network interface first.")
            return

        try:
            ip, subnet, gateway = self.read_form()
        except ValueError as exc:
            messagebox.showerror("Invalid Configuration", str(exc))
            return

        duplicate = next(
            (
                item
                for item in self.interfaces
                if item["name"] != interface["name"] and item.get("ip") == ip
            ),
            None,
        )
        if duplicate and not messagebox.askyesno(
            "IP Already Assigned",
            f"{ip} is currently shown on {duplicate['name']}.\n\nApply it to {interface['name']} anyway?",
        ):
            return

        args = [
            "netsh",
            "interface",
            "ipv4",
            "set",
            "address",
            f"name={interface['name']}",
            "source=static",
            f"address={ip}",
            f"mask={subnet}",
            f"gateway={gateway or 'none'}",
        ]
        self.set_status(f"Applying static IP to {interface['name']}...")
        result = run_hidden(args)
        if result.returncode != 0:
            messagebox.showerror(
                "IP Change Failed",
                result.stderr.strip() or result.stdout.strip() or "netsh returned an error.",
            )
            self.set_status("Static IP change failed.")
            return

        self.set_status(f"Static IP applied to {interface['name']}.")
        self.refresh_interfaces()

    def enable_dhcp(self):
        interface = self.get_selected_interface()
        if not interface:
            messagebox.showerror("No Interface", "Select a network interface first.")
            return

        if not messagebox.askyesno(
            "Enable DHCP",
            f"Switch {interface['name']} to DHCP?",
        ):
            return

        args = [
            "netsh",
            "interface",
            "ipv4",
            "set",
            "address",
            f"name={interface['name']}",
            "source=dhcp",
        ]
        self.set_status(f"Enabling DHCP on {interface['name']}...")
        result = run_hidden(args)
        if result.returncode != 0:
            messagebox.showerror(
                "DHCP Failed",
                result.stderr.strip() or result.stdout.strip() or "netsh returned an error.",
            )
            self.set_status("DHCP change failed.")
            return

        self.set_status(f"DHCP enabled on {interface['name']}.")
        self.refresh_interfaces()

    def fill_from_current(self):
        interface = self.get_selected_interface()
        if not interface:
            return
        self.ip_var.set(interface.get("ip", ""))
        self.subnet_var.set(interface.get("subnet", "") or "255.255.255.0")
        self.gateway_var.set(interface.get("gateway", ""))
        self.set_status("Current configuration loaded into the form.")

    def clear_form(self):
        self.ip_var.set("")
        self.subnet_var.set("255.255.255.0")
        self.gateway_var.set("")
        self.set_status("Form cleared.")

    def update_preset_menu(self):
        names = [preset["name"] for preset in self.presets if preset.get("name")]
        if names:
            self.preset_menu.configure(values=names, state="normal")
            if self.preset_var.get() not in names:
                self.preset_var.set(names[0])
        else:
            self.preset_menu.configure(values=["No presets saved"], state="disabled")
            self.preset_var.set("No presets saved")

    def get_selected_preset(self):
        selected = self.preset_var.get()
        return next((preset for preset in self.presets if preset.get("name") == selected), None)

    def fill_from_selected_preset(self):
        preset = self.get_selected_preset()
        if not preset:
            return
        self.ip_var.set(preset.get("ip", ""))
        self.subnet_var.set(preset.get("subnet", "") or "255.255.255.0")
        self.gateway_var.set(preset.get("gateway", ""))
        self.set_status(f"Preset loaded: {preset['name']}")

    def apply_selected_preset(self):
        if not self.get_selected_preset():
            return
        self.fill_from_selected_preset()
        self.apply_static_ip()

    def save_current_as_preset(self):
        try:
            ip, subnet, gateway = self.read_form()
        except ValueError as exc:
            messagebox.showerror("Invalid Preset", str(exc))
            return

        name = preset_name(ip, subnet)
        preset = {
            "name": name,
            "ip": ip,
            "subnet": subnet,
            "gateway": gateway,
        }
        for index, item in enumerate(self.presets):
            if item.get("name") == name:
                self.presets[index] = preset
                break
        else:
            self.presets.append(preset)

        save_presets(self.presets)
        self.update_preset_menu()
        self.preset_var.set(name)
        self.set_status(f"Preset saved: {name}")

    def delete_selected_preset(self):
        preset = self.get_selected_preset()
        if not preset:
            return
        if not messagebox.askyesno("Delete Preset", f"Delete preset '{preset['name']}'?"):
            return

        self.presets = [item for item in self.presets if item.get("name") != preset["name"]]
        save_presets(self.presets)
        self.update_preset_menu()
        self.set_status(f"Preset deleted: {preset['name']}")

    def import_presets_from_file(self):
        path = filedialog.askopenfilename(
            title="Import presets",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialdir=APP_DATA_DIR,
        )
        if not path:
            return

        try:
            imported = import_presets(path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            messagebox.showerror("Import Failed", str(exc))
            return

        by_name = {preset.get("name"): preset for preset in normalize_presets(self.presets) if preset.get("name")}
        for preset in imported:
            normalized = normalize_preset(preset)
            if normalized.get("name"):
                by_name[normalized["name"]] = normalized

        self.presets = list(by_name.values())
        save_presets(self.presets)
        self.update_preset_menu()
        self.set_status(f"Imported {len(imported)} preset(s).")

    def export_presets_to_file(self):
        path = filedialog.asksaveasfilename(
            title="Export presets",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialdir=APP_DATA_DIR,
        )
        if not path:
            return

        try:
            export_presets(path, self.presets)
        except OSError as exc:
            messagebox.showerror("Export Failed", str(exc))
            return
        self.set_status(f"Presets exported to {path}")

    def set_status(self, text):
        self.status_var.set(text)
        self.update_idletasks()

    def show_about(self):
        messagebox.showinfo(
            "About IP Switcher",
            f"{APP_NAME} {APP_VERSION}\n\nSimple Windows IPv4 configuration for network interfaces.\n{ORG_NAME}",
        )

    def close(self):
        save_presets(self.presets)
        self.destroy()


def create_ip_updater():
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    app = IPSwitcherApp()
    app.mainloop()


if __name__ == "__main__":
    create_ip_updater()
