import os
import sys

from .constants import APP_NAME


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
PHONE_CONFIG_STATE_FILE = os.path.join(APP_DATA_DIR, "phone-configurator-state.json")
PHONE_CONFIG_LOG_FILE = os.path.join(APP_DATA_DIR, "phone-configurator-log.csv")
PHONE_CONFIG_PENDING_LOG_FILE = os.path.join(APP_DATA_DIR, "phone-configurator-log-pending.csv")
PHONE_CONFIG_SETTINGS_FILE = os.path.join(APP_DATA_DIR, "phone-configurator-settings.json")


def resource_path(filename):
    # Anchored two directories up from this file (src/) rather than this module's
    # own directory, since bundled assets (icon, VERSION) live next to the package,
    # not inside it.
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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
