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
from ...ui_helpers import raise_dialog
from ...winutil import apply_dark_window_frame
from .config import phone_load_settings, phone_resolve_settings, phone_save_settings
from .history import (
    phone_ensure_config_log_file,
    phone_load_state,
    phone_next_target_ip,
    phone_read_config_log,
)
from .ssh_ops import phone_configure_next

HINT_COLOR = "#7d8b99"
ERROR_COLOR = "#f0605a"
ENTRY_BORDER_COLOR = "#34414d"
PHONE_DHCP_KEYS = {"staging_interface", "dhcp_server_ip", "dhcp_pool_start", "dhcp_pool_end"}
PHONE_ADVANCED_KEYS = {
    "ssh_port",
    "dhcp_ssh_probe_seconds",
    "dhcp_lease_seconds",
    "dhcp_wait_seconds",
    "ping_timeout_seconds",
    "ping_interval_seconds",
}


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
    interface_menu = None
    rescan_button = None
    save_button = None
    form_fields = {}
    validation_job = {"id": None}
    advanced_state = {"open": False}

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
        schedule_validation()
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
        config, errors, _hints = phone_resolve_settings(settings_payload())
        if errors:
            messagebox.showerror(
                "Check Settings",
                "Fix these settings before configuring a phone:\n\n"
                + "\n".join(f"• {message}" for message in errors.values()),
                parent=window,
            )
            show_settings_view()
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
        config, errors, _hints = phone_resolve_settings(settings_payload())
        if errors:
            count = len(errors)
            summary_label(summary_panel, "Settings", f"{count} setting{'s' if count != 1 else ''} to fix", 1)
            ctk.CTkButton(
                summary_panel,
                text="Open Settings",
                width=120,
                command=show_settings_view,
                fg_color="#1f6f8b",
                hover_color="#2382a4",
            ).grid(row=2, column=0, columnspan=2, sticky="w", padx=14, pady=(4, 14))
        else:
            try:
                next_ip = str(phone_next_target_ip(config, phone_load_state()))
            except Exception as exc:
                next_ip = str(exc)
            summary_label(summary_panel, "Next IP", next_ip, 1)
            summary_label(summary_panel, "Phone range", f"{config.target_start} - {config.target_end}", 2)
            summary_label(summary_panel, "Network", f"{config.scan_subnet}  ({config.netmask})", 3)
            summary_label(summary_panel, "Gateway / TFTP", f"{config.gateway} / {config.tftp_server}", 4)
            if config.use_dhcp_server:
                summary_label(summary_panel, "Interface", f"{config.staging_interface} as {config.dhcp_server_ip}", 5)
                summary_label(summary_panel, "DHCP pool", f"{config.dhcp_pool_start} - {config.dhcp_pool_end}", 6)
            else:
                summary_label(summary_panel, "Staging", "SSH scan mode (no DHCP server)", 5)

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

    def add_settings_panel(parent, title, row, subtitle=None):
        panel = ctk.CTkFrame(parent, fg_color="#182029", corner_radius=8)
        panel.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        panel.grid_columnconfigure((0, 1, 2), weight=1, uniform="settings")
        ctk.CTkLabel(
            panel,
            text=title,
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color="#f7fafc",
        ).grid(row=0, column=0, columnspan=3, sticky="w", padx=14, pady=(14, 0))
        if subtitle:
            ctk.CTkLabel(panel, text=subtitle, text_color=HINT_COLOR, anchor="w").grid(
                row=1, column=0, columnspan=3, sticky="w", padx=14
            )
        return panel

    def field_message(frame, key, row, note, entry=None):
        message = ctk.CTkLabel(
            frame,
            text=note,
            text_color=HINT_COLOR,
            anchor="w",
            justify="left",
            wraplength=290,
            font=ctk.CTkFont(size=11),
        )
        message.grid(row=row, column=0, sticky="ew", pady=(3, 0))
        form_fields[key] = {"entry": entry, "message": message, "note": note}

    def form_field(parent, key, label, row, column, note="", show=""):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=row, column=column, sticky="new", padx=14, pady=(12, 6))
        frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(frame, text=label, text_color="#9aa8b6").grid(row=0, column=0, sticky="w")
        entry = ctk.CTkEntry(
            frame,
            textvariable=values[key],
            border_width=1,
            border_color=ENTRY_BORDER_COLOR,
            fg_color="#101418",
            show=show,
        )
        entry.grid(row=1, column=0, sticky="ew", pady=(5, 0))
        field_message(frame, key, 2, note, entry)
        return entry

    def refresh_validation():
        validation_job["id"] = None
        if not window.winfo_exists():
            return
        _config, errors, hints = phone_resolve_settings(settings_payload())
        use_dhcp = use_dhcp_var.get()
        for key, field in form_fields.items():
            if not field["message"].winfo_exists():
                continue
            raw = values[key].get().strip()
            if key in errors:
                text, color, border = errors[key], ERROR_COLOR, ERROR_COLOR
            else:
                hint = hints.get(key, "")
                # Echoing a value the user typed in full adds nothing; show the note instead.
                text = hint if hint and hint != raw else field["note"]
                color, border = HINT_COLOR, ENTRY_BORDER_COLOR
            if key in PHONE_DHCP_KEYS and not use_dhcp:
                text, color, border = "Not used without the built-in DHCP server.", HINT_COLOR, ENTRY_BORDER_COLOR
            field["message"].configure(text=text, text_color=color)
            if field["entry"] is not None and field["entry"].winfo_exists():
                field["entry"].configure(
                    border_color=border,
                    state="normal" if use_dhcp or key not in PHONE_DHCP_KEYS else "disabled",
                )
        if interface_menu is not None and interface_menu.winfo_exists() and phone_interfaces:
            interface_menu.configure(state="normal" if use_dhcp else "disabled")
        if errors.keys() & PHONE_ADVANCED_KEYS and not advanced_state["open"]:
            toggle_advanced()
        if save_button is not None and save_button.winfo_exists():
            save_button.configure(state="disabled" if errors else "normal")
            # Name the first problem: it may sit in a panel scrolled out of view.
            first = next(iter(errors.values()), "")
            extra = f" (+{len(errors) - 1} more)" if len(errors) > 1 else ""
            status_var.set(f"{first}{extra}" if errors else "All settings are valid.")

    def schedule_validation(*_args):
        if validation_job["id"] is None and window.winfo_exists():
            validation_job["id"] = window.after(120, refresh_validation)

    def toggle_advanced():
        advanced_state["open"] = not advanced_state["open"]
        panel = advanced_state.get("panel")
        button = advanced_state.get("button")
        if panel is None or not panel.winfo_exists():
            return
        if advanced_state["open"]:
            panel.grid()
        else:
            panel.grid_remove()
        button.configure(text=("Hide" if advanced_state["open"] else "Show") + " advanced settings")

    def save_settings_from_view():
        config, errors, _hints = phone_resolve_settings(settings_payload())
        if errors:
            refresh_validation()
            return
        # Store "10.32.10.64 255.255.255.192" and similar as plain CIDR.
        values["scan_subnet"].set(str(config.scan_subnet))
        phone_save_settings(settings_payload())
        status_var.set("Phone configurator settings saved.")
        show_run_view()

    def cancel_settings_view():
        load_saved_settings_into_form()
        status_var.set("Settings changes discarded.")
        show_run_view()

    def show_settings_view():
        nonlocal interface_menu, rescan_button, save_button
        clear_frame(content)
        clear_frame(footer)
        form_fields.clear()
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

        network_panel = add_settings_panel(
            settings_scroll,
            "Phone Network",
            0,
            "The netmask and broadcast follow from the network. Addresses can be typed in full or as the last number.",
        )
        form_field(network_panel, "scan_subnet", "Network", 2, 0, "For example 10.32.10.64/26")
        form_field(network_panel, "target_start", "First phone IP", 2, 1, "For example 115")
        form_field(network_panel, "target_end", "Last phone IP", 2, 2, "For example 119")
        form_field(network_panel, "gateway", "Gateway", 3, 0, "Leave blank to use the last usable address")
        form_field(network_panel, "tftp_server", "TFTP server", 3, 1, "For example 114")

        dhcp_panel = add_settings_panel(
            settings_scroll,
            "Staging",
            1,
            "The PC gives the phone a temporary address, then sets its static IP over SSH.",
        )
        ctk.CTkCheckBox(
            dhcp_panel,
            text="Run built-in DHCP server",
            variable=use_dhcp_var,
            text_color="#d8e0e7",
            fg_color="#1f6f8b",
            hover_color="#2382a4",
        ).grid(row=2, column=0, sticky="w", padx=14, pady=(30, 6))
        interface_frame = ctk.CTkFrame(dhcp_panel, fg_color="transparent")
        interface_frame.grid(row=2, column=1, columnspan=2, sticky="new", padx=14, pady=(12, 6))
        interface_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(interface_frame, text="Phone is connected to", text_color="#9aa8b6").grid(
            row=0, column=0, sticky="w"
        )
        interface_menu = ctk.CTkOptionMenu(
            interface_frame,
            variable=staging_interface_var,
            values=["Loading interfaces..."],
            fg_color="#101418",
            button_color="#1f6f8b",
            button_hover_color="#2382a4",
            dropdown_fg_color="#182029",
            dropdown_hover_color="#1f6f8b",
            state="disabled",
        )
        interface_menu.grid(row=1, column=0, sticky="ew", pady=(5, 0))
        rescan_button = ctk.CTkButton(
            interface_frame,
            text="Refresh",
            width=86,
            command=refresh_phone_interfaces_async,
            fg_color="#2f3b46",
            hover_color="#3b4a57",
        )
        rescan_button.grid(row=1, column=1, sticky="w", padx=(8, 0), pady=(5, 0))
        field_message(interface_frame, "staging_interface", 2, "Network interface on this PC")
        refresh_phone_interfaces_async()
        form_field(dhcp_panel, "dhcp_server_ip", "PC staging IP", 3, 0, "Leave blank for auto")
        form_field(dhcp_panel, "dhcp_pool_start", "DHCP pool start", 3, 1, "Leave blank for auto")
        form_field(dhcp_panel, "dhcp_pool_end", "DHCP pool end", 3, 2, "Leave blank for auto")

        ssh_panel = add_settings_panel(settings_scroll, "Phone Login", 2)
        form_field(ssh_panel, "ssh_username", "SSH username", 1, 0)
        form_field(ssh_panel, "ssh_password", "SSH password", 1, 1, show="*")

        advanced_button = ctk.CTkButton(
            settings_scroll,
            text="Show advanced settings",
            width=190,
            command=toggle_advanced,
            fg_color="#2f3b46",
            hover_color="#3b4a57",
        )
        advanced_button.grid(row=3, column=0, sticky="w", pady=(0, 12))
        advanced_panel = add_settings_panel(settings_scroll, "Advanced", 4, "Timeouts in seconds. The defaults suit most phones.")
        form_field(advanced_panel, "ssh_port", "SSH port", 2, 0)
        form_field(advanced_panel, "dhcp_ssh_probe_seconds", "SSH probe", 2, 1, "Wait for SSH after DHCP")
        form_field(advanced_panel, "dhcp_lease_seconds", "DHCP lease", 2, 2)
        form_field(advanced_panel, "dhcp_wait_seconds", "DHCP wait", 3, 0, "Wait for the phone to ask for an address")
        form_field(advanced_panel, "ping_timeout_seconds", "Ping timeout", 3, 1, "Wait for the phone on its new IP")
        form_field(advanced_panel, "ping_interval_seconds", "Ping interval", 3, 2)
        advanced_state.update(panel=advanced_panel, button=advanced_button, open=False)
        advanced_panel.grid_remove()

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
        save_button = ctk.CTkButton(
            footer,
            text="Save Settings",
            width=128,
            command=save_settings_from_view,
            fg_color="#2d8a66",
            hover_color="#35a579",
        )
        save_button.grid(row=0, column=2)
        refresh_validation()

    for variable in [*values.values(), use_dhcp_var]:
        variable.trace_add("write", schedule_validation)
    show_run_view()
    poll_log_queue()
