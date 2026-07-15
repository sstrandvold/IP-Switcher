import json
import sys
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

from . import async_task, tools
from .constants import APP_NAME, ORG_NAME
from .network import get_interfaces, validate_ipv4, validate_subnet_mask
from .paths import APP_DATA_DIR, APP_VERSION, resource_path
from .presets import (
    export_presets,
    import_presets,
    load_presets,
    normalize_preset,
    normalize_presets,
    preset_name,
    save_presets,
)
from .ui_helpers import show_popup_menu
from .winutil import apply_dark_window_frame, run_hidden


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
        self._busy = False

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
            "Tools": [(label, (lambda open_dialog=open_dialog: open_dialog(self))) for label, open_dialog in tools.TOOLS],
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
            button.configure(command=lambda target=button, menu_items=items: show_popup_menu(self, target, menu_items))

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

        self.refresh_button = ctk.CTkButton(
            header,
            text="Refresh",
            width=110,
            command=self.refresh_interfaces,
            fg_color="#1f6f8b",
            hover_color="#2382a4",
        )
        self.refresh_button.grid(row=0, column=2, padx=22, pady=16)

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

        self.busy_progress = ctk.CTkProgressBar(
            status_bar,
            mode="indeterminate",
            fg_color="#151b22",
            progress_color="#1f6f8b",
        )
        self.busy_progress.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 8))
        self.busy_progress.grid_remove()

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

        self.apply_button = ctk.CTkButton(
            actions,
            text="Apply Static IP",
            command=self.apply_static_ip,
            fg_color="#2d8a66",
            hover_color="#35a579",
        )
        self.apply_button.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.dhcp_button = ctk.CTkButton(
            actions,
            text="Enable DHCP",
            command=self.enable_dhcp,
            fg_color="#1f6f8b",
            hover_color="#2382a4",
        )
        self.dhcp_button.grid(row=0, column=1, sticky="ew", padx=8)
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

    def set_busy_ui(self, busy, text=None):
        state = "disabled" if busy else "normal"
        for button in (self.refresh_button, self.apply_button, self.dhcp_button):
            button.configure(state=state)
        if busy:
            self.busy_progress.grid()
            self.busy_progress.start()
            if text:
                self.set_status(text)
        else:
            self.busy_progress.stop()
            self.busy_progress.grid_remove()

    def run_async(self, work, on_done, busy_text):
        if self._busy:
            return
        self._busy = True

        def on_busy():
            self.set_busy_ui(True, busy_text)

        def on_idle():
            self._busy = False
            self.set_busy_ui(False)

        async_task.run_async(self, work, on_done, on_busy=on_busy, on_idle=on_idle)

    def refresh_interfaces(self):
        if not sys.platform.startswith("win"):
            messagebox.showerror("Unsupported OS", "IP Switcher can only change IP settings on Windows.")
            return

        self.render_loading_placeholder()

        def on_done(kind, payload):
            if kind == "error":
                messagebox.showerror("Interface Error", str(payload))
                self.set_status("Could not read network interfaces.")
                return

            self.apply_interfaces_result(payload)
            if self.interfaces:
                self.set_status(f"Found {len(self.interfaces)} network interface(s).")
            else:
                self.set_status("No network interfaces found.")

        self.run_async(get_interfaces, on_done, "Refreshing interfaces...")

    def apply_interfaces_result(self, interfaces):
        self.interfaces = interfaces
        self.render_interfaces()
        if self.interfaces:
            preferred = self.selected_interface or self.interfaces[0]["name"]
            if preferred not in {item["name"] for item in self.interfaces}:
                preferred = self.interfaces[0]["name"]
            self.select_interface(preferred)
        else:
            self.select_interface(None)

    def render_loading_placeholder(self):
        for child in self.interface_list.winfo_children():
            child.destroy()
        self.interface_buttons.clear()
        ctk.CTkLabel(
            self.interface_list,
            text="Loading interfaces...",
            text_color="#8fa0af",
        ).grid(row=0, column=0, sticky="ew", padx=6, pady=10)

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

        def work():
            result = run_hidden(args)
            if result.returncode != 0:
                raise RuntimeError(
                    result.stderr.strip() or result.stdout.strip() or "netsh returned an error."
                )
            return get_interfaces()

        def on_done(kind, payload):
            if kind == "error":
                messagebox.showerror("IP Change Failed", str(payload))
                self.set_status("Static IP change failed.")
                return
            self.selected_interface = interface["name"]
            self.apply_interfaces_result(payload)
            self.set_status(f"Static IP applied to {interface['name']}.")

        self.run_async(work, on_done, f"Applying static IP to {interface['name']}...")

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

        def work():
            result = run_hidden(args)
            if result.returncode != 0:
                raise RuntimeError(
                    result.stderr.strip() or result.stdout.strip() or "netsh returned an error."
                )
            return get_interfaces()

        def on_done(kind, payload):
            if kind == "error":
                messagebox.showerror("DHCP Failed", str(payload))
                self.set_status("DHCP change failed.")
                return
            self.selected_interface = interface["name"]
            self.apply_interfaces_result(payload)
            self.set_status(f"DHCP enabled on {interface['name']}.")

        self.run_async(work, on_done, f"Enabling DHCP on {interface['name']}...")

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
