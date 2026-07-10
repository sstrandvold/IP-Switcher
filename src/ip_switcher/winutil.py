import ctypes
import subprocess
import sys
import tkinter as tk

from .constants import (
    CREATE_NO_WINDOW,
    DARK_BORDER_COLOR,
    DARK_CAPTION_COLOR,
    DWMWA_BORDER_COLOR,
    DWMWA_CAPTION_COLOR,
    DWMWA_TEXT_COLOR,
    DWMWA_USE_IMMERSIVE_DARK_MODE,
    DWMWA_USE_IMMERSIVE_DARK_MODE_OLD,
    LIGHT_TEXT_COLOR,
)


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
