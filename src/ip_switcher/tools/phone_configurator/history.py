import csv
import ipaddress
import json
import os
import time

from ...constants import PHONE_CONFIG_LOG_FIELDS
from ...paths import (
    APP_DATA_DIR,
    PHONE_CONFIG_LOG_FILE,
    PHONE_CONFIG_PENDING_LOG_FILE,
    PHONE_CONFIG_STATE_FILE,
)


def phone_load_state():
    if not os.path.exists(PHONE_CONFIG_STATE_FILE):
        return {"phones": []}
    with open(PHONE_CONFIG_STATE_FILE, "r", encoding="utf-8") as handle:
        return json.load(handle)


def phone_save_state(state):
    os.makedirs(APP_DATA_DIR, exist_ok=True)
    with open(PHONE_CONFIG_STATE_FILE, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)


def phone_write_config_log_row(path, record):
    file_exists = os.path.exists(path)
    with open(path, "a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=PHONE_CONFIG_LOG_FIELDS)
        if not file_exists:
            writer.writeheader()
        writer.writerow({key: record.get(key, "") for key in PHONE_CONFIG_LOG_FIELDS})
    return path


def phone_append_config_log(record):
    os.makedirs(APP_DATA_DIR, exist_ok=True)
    try:
        return phone_write_config_log_row(PHONE_CONFIG_LOG_FILE, record)
    except OSError:
        return phone_write_config_log_row(PHONE_CONFIG_PENDING_LOG_FILE, record)


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
