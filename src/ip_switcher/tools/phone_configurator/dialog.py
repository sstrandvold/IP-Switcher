import os
import queue
import threading
import time
import tkinter as tk
from tkinter import messagebox

import customtkinter as ctk

from ...constants import PHONE_CONFIG_DEFAULTS
from ...network import get_interfaces
from ...paths import APP_DATA_DIR, PHONE_CONFIG_LOG_FILE, PHONE_CONFIG_PENDING_LOG_FILE
from ...ui_helpers import dialog_entry_group, raise_dialog
from ...winutil import apply_dark_window_frame
from .config import PhoneConfig, phone_load_settings, phone_save_settings
from .history import (
    phone_ensure_config_log_file,
    phone_load_state,
    phone_next_target_ip,
    phone_read_config_log,
)
from .ssh_ops import phone_configure_next


def show(app):
    if app.phone_config_window and app.phone_config_window.winfo_exists():
        raise_dialog(app.phone_config_window)
        return

    window = ctk.CTkToplevel(app)
    app.phone_config_window = window
    window.title("Phone Configurator")
    window.geometry("1120x760")
    window.minsize(980, 680)
    window.configure(fg_color="#101418")
    window.grid_columnconfigure(0, weight=1)
    window.grid_rowconfigure(1, weight=1)
    window.transient(app)
    window.protocol("WM_DELETE_WINDOW", window.destroy)
    window.after(50, lambda: apply_dark_window_frame(window))
    window.after(100, lambda: raise_dialog(window))

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

    def apply_phone_interfaces(discovered):
        nonlocal phone_interfaces
        phone_interfaces = discovered
        names = [item["name"] for item in phone_interfaces]
        if names and staging_interface_var.get() not in names:
            selected = app.selected_interface if app.selected_interface in names else ""
            if not selected:
                active = next((item["name"] for item in phone_interfaces if item.get("status") == "Up"), "")
                selected = active or names[0]
            staging_interface_var.set(selected)
        if interface_menu is not None and interface_menu.winfo_exists():
            interface_menu.configure(
                values=names or ["No interfaces found"],
                state="normal" if names else "disabled",
            )
        if rescan_button is not None and rescan_button.winfo_exists():
            rescan_button.configure(state="normal")
        return names

    def refresh_phone_interfaces_async():
        if interface_menu is not None and interface_menu.winfo_exists():
            interface_menu.configure(values=["Loading interfaces..."], state="disabled")
        if rescan_button is not None and rescan_button.winfo_exists():
            rescan_button.configure(state="disabled")
        status_var.set("Scanning network interfaces...")

        def worker():
            try:
                discovered = get_interfaces()
            except Exception:
                discovered = []
            log_queue.put(("interfaces", discovered))

        threading.Thread(target=worker, daemon=True).start()

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
        log_window.after(100, lambda: raise_dialog(log_window))

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
            elif kind == "interfaces":
                names = apply_phone_interfaces(message)
                status_var.set(
                    f"Found {len(names)} network interface(s)." if names else "No network interfaces found."
                )
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
        dialog_entry_group(network_panel, "Scan subnet", values["scan_subnet"], 1, 0)
        dialog_entry_group(network_panel, "Target start", values["target_start"], 1, 1)
        dialog_entry_group(network_panel, "Target end", values["target_end"], 1, 2)
        dialog_entry_group(network_panel, "Netmask", values["netmask"], 2, 0)
        dialog_entry_group(network_panel, "Gateway", values["gateway"], 2, 1)
        dialog_entry_group(network_panel, "TFTP server", values["tftp_server"], 2, 2)

        dhcp_panel = add_settings_panel(settings_scroll, "DHCP Staging", 1)
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
            values=["Loading interfaces..."],
            fg_color="#101418",
            button_color="#1f6f8b",
            button_hover_color="#2382a4",
            dropdown_fg_color="#182029",
            dropdown_hover_color="#1f6f8b",
            state="disabled",
        )
        interface_menu.grid(row=2, column=1, sticky="ew", padx=14, pady=(5, 14))
        rescan_button = ctk.CTkButton(
            dhcp_panel,
            text="Refresh Interfaces",
            width=136,
            command=refresh_phone_interfaces_async,
            fg_color="#2f3b46",
            hover_color="#3b4a57",
        )
        rescan_button.grid(row=2, column=2, sticky="w", padx=14, pady=(5, 14))
        refresh_phone_interfaces_async()
        dialog_entry_group(dhcp_panel, "Interface IP to set", values["dhcp_server_ip"], 3, 0)
        dialog_entry_group(dhcp_panel, "DHCP pool start", values["dhcp_pool_start"], 3, 1)
        dialog_entry_group(dhcp_panel, "DHCP pool end", values["dhcp_pool_end"], 3, 2)
        dialog_entry_group(dhcp_panel, "Lease seconds", values["dhcp_lease_seconds"], 4, 0)
        dialog_entry_group(dhcp_panel, "DHCP wait", values["dhcp_wait_seconds"], 4, 1)

        ssh_panel = add_settings_panel(settings_scroll, "SSH", 2)
        dialog_entry_group(ssh_panel, "Username", values["ssh_username"], 1, 0)
        dialog_entry_group(ssh_panel, "SSH port", values["ssh_port"], 1, 1)
        dialog_entry_group(ssh_panel, "SSH probe seconds", values["dhcp_ssh_probe_seconds"], 1, 2)
        password_entry = dialog_entry_group(ssh_panel, "Password", values["ssh_password"], 2, 0)
        password_entry.configure(show="*")

        verify_panel = add_settings_panel(settings_scroll, "Verification", 3)
        dialog_entry_group(verify_panel, "Ping timeout", values["ping_timeout_seconds"], 1, 0)
        dialog_entry_group(verify_panel, "Ping interval", values["ping_interval_seconds"], 1, 1)

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
