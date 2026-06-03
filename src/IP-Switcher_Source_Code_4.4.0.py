import ipaddress
import json
import os
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk


APP_NAME = "IP Switcher"
APP_VERSION = "4.4.0"
ORG_NAME = "Trafsys AS"
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


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


class IPSwitcherApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION}")
        self.geometry("980x680")
        self.minsize(880, 600)

        self.interfaces = []
        self.interface_buttons = {}
        self.selected_interface = None
        self.presets = load_presets()

        self.ip_var = tk.StringVar()
        self.subnet_var = tk.StringVar(value="255.255.255.0")
        self.gateway_var = tk.StringVar()
        self.preset_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")

        self.current_values = {}

        self.configure(fg_color="#101418")
        self.set_icon()
        self.build_menu()
        self.build_layout()
        self.protocol("WM_DELETE_WINDOW", self.close)

        self.update_preset_menu()
        self.after(100, self.refresh_interfaces)

    def set_icon(self):
        try:
            self.iconbitmap(resource_path("icon3.ico"))
        except tk.TclError:
            pass

    def build_menu(self):
        menu_bar = tk.Menu(self)
        file_menu = tk.Menu(menu_bar, tearoff=False)
        file_menu.add_command(label="Import presets...", command=self.import_presets_from_file)
        file_menu.add_command(label="Export presets...", command=self.export_presets_to_file)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.close)
        menu_bar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menu_bar, tearoff=False)
        help_menu.add_command(label="About", command=self.show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menu_bar)

    def build_layout(self):
        self.grid_columnconfigure(0, minsize=305)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="#151b22", corner_radius=0)
        header.grid(row=0, column=0, columnspan=2, sticky="ew")
        header.grid_columnconfigure(0, weight=1)

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

        ctk.CTkButton(
            header,
            text="Refresh",
            width=110,
            command=self.refresh_interfaces,
            fg_color="#1f6f8b",
            hover_color="#2382a4",
        ).grid(row=0, column=1, padx=22, pady=16)

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
        main.grid(row=1, column=1, sticky="nsew", padx=22, pady=22)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(3, weight=1)

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

        self.status_label = ctk.CTkLabel(
            main,
            textvariable=self.status_var,
            anchor="w",
            text_color="#9aa8b6",
        )
        self.status_label.grid(row=4, column=0, sticky="ew", pady=(14, 0))

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
