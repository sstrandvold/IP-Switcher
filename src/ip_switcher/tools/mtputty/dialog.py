import os
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

from ...constants import MTPUTTY_COMMAND_OPTIONS
from ...paths import APP_DATA_DIR
from ...ui_helpers import dialog_entry_group
from ...winutil import apply_dark_window_frame
from .xml_builder import export_mtputty_xml_files, mtputty_category_name, parse_multiping_file


def show(app):
    if app.mtputty_window and app.mtputty_window.winfo_exists():
        app.mtputty_window.focus()
        return

    window = ctk.CTkToplevel(app)
    app.mtputty_window = window
    window.title("MTPuTTY XML Generator")
    window.geometry("820x820")
    window.minsize(740, 720)
    window.transient(app)
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

    username_entry = dialog_entry_group(config_panel, "Username", username_var, 0, 0)
    port_entry = dialog_entry_group(config_panel, "SSH port", port_var, 0, 1)
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
