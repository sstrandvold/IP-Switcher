import json
import os

from .network import subnet_mask_to_prefix, validate_ipv4, validate_subnet_mask
from .paths import APP_DATA_DIR, APP_VERSION, OLD_AUTOSAVE_FILE, PRESETS_FILE


def preset_name(ip, subnet):
    return f"{ip}/{subnet_mask_to_prefix(subnet)}"


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
