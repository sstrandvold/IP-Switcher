import tkinter as tk

import customtkinter as ctk


def show_popup_menu(parent, anchor, items):
    menu = tk.Menu(
        parent,
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


def raise_dialog(window):
    try:
        window.lift()
        window.focus_force()
        window.attributes("-topmost", True)
        window.after(250, lambda: window.attributes("-topmost", False) if window.winfo_exists() else None)
    except tk.TclError:
        pass


def dialog_entry_group(parent, label, variable, row, column):
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
