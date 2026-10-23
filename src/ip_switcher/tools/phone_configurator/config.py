import dataclasses
import ipaddress
import json
import os

from ...constants import PHONE_CONFIG_DEFAULTS, PHONE_CONFIG_SETTING_KEYS
from ...paths import APP_DATA_DIR, PHONE_CONFIG_SETTINGS_FILE

# Phones are staged one at a time, so a small pool is plenty and leaves the rest of the
# network free for the static range.
PHONE_DHCP_POOL_SIZE = 10


class PhoneNeedsNetwork(ValueError):
    """A shorthand address that cannot be resolved until the network field is valid."""


@dataclasses.dataclass(frozen=True)
class PhoneConfig:
    staging_interface: str
    scan_subnet: ipaddress.IPv4Network
    target_start: ipaddress.IPv4Address
    target_end: ipaddress.IPv4Address
    gateway: str
    tftp_server: str
    ssh_username: str
    ssh_password: str
    ssh_port: int
    dhcp_server_ip: ipaddress.IPv4Address
    dhcp_pool_start: ipaddress.IPv4Address
    dhcp_pool_end: ipaddress.IPv4Address
    dhcp_lease_seconds: int
    dhcp_wait_seconds: int
    dhcp_ssh_probe_seconds: int
    ping_timeout_seconds: int
    ping_interval_seconds: int
    use_dhcp_server: bool

    @property
    def netmask(self):
        return str(self.scan_subnet.netmask)

    @classmethod
    def from_values(cls, values):
        config, errors, _hints = phone_resolve_settings(values)
        if errors:
            raise ValueError("\n".join(errors.values()))
        return config


def phone_parse_network(text):
    text = " ".join(str(text).split())
    if not text:
        raise ValueError("Network is required, for example 10.32.10.64/26.")
    # Accept "10.32.10.64 255.255.255.192" as well as CIDR.
    if "/" not in text and " " in text:
        text = text.replace(" ", "/", 1)
    if "/" not in text:
        raise ValueError("Network needs a prefix length, for example 10.32.10.64/26.")
    try:
        network = ipaddress.IPv4Network(text, strict=False)
    except ValueError as exc:
        raise ValueError("Network must look like 10.32.10.64/26 or 10.32.10.64 255.255.255.192.") from exc
    if network.prefixlen > 29:
        raise ValueError("Network is too small. Use /29 or larger.")
    return network


def phone_parse_address(text, network, label, required=True):
    text = str(text).strip()
    if not text:
        if required:
            raise ValueError(f"{label} is required.")
        return None
    if text.isdigit():
        if network is None:
            raise PhoneNeedsNetwork(f"{label}: enter a full IP address until the network is valid.")
        if int(text) > 255:
            raise ValueError(f"{label}: a last octet must be between 0 and 255.")
        address = ipaddress.IPv4Address((int(network.network_address) & ~0xFF) | int(text))
    else:
        try:
            address = ipaddress.IPv4Address(text)
        except ValueError as exc:
            raise ValueError(f"{label} must be an IPv4 address, or just the last number (for example 115).") from exc
    if network is not None:
        if address not in network:
            raise ValueError(f"{label} {address} is outside the network {network}.")
        if address in (network.network_address, network.broadcast_address):
            raise ValueError(f"{label} {address} is the network or broadcast address.")
    return address


def phone_parse_int(text, label, minimum, maximum=None):
    text = str(text).strip()
    if not text.isdigit():
        raise ValueError(f"{label} must be a whole number.")
    value = int(text)
    if value < minimum or (maximum is not None and value > maximum):
        limit = f"between {minimum} and {maximum}" if maximum is not None else f"at least {minimum}"
        raise ValueError(f"{label} must be {limit}.")
    return value


def phone_free_runs(network, reserved):
    first = int(network.network_address) + 1
    last = int(network.broadcast_address) - 1
    runs = []
    previous = first - 1
    for point in sorted(value for value in reserved if first <= value <= last) + [last + 1]:
        if point - previous > 1:
            runs.append((previous + 1, point - 1))
        previous = point
    return runs


def phone_longest_free_run(network, reserved, minimum_size):
    runs = [run for run in phone_free_runs(network, reserved) if run[1] - run[0] + 1 >= minimum_size]
    if not runs:
        return None
    # Ties go to the highest run: low addresses are where switches and other infra usually live.
    return max(runs, key=lambda run: (run[1] - run[0], run[0]))


def phone_resolve_settings(values):
    """Parse the raw form values.

    Returns (config, errors, hints). errors and hints are keyed by setting name so the
    form can show each message under its field; config is None when there are errors.
    """
    errors = {}
    hints = {}

    def attempt(key, parse):
        try:
            return parse()
        except PhoneNeedsNetwork:
            # The network field already carries the error; don't repeat it on every field.
            return None
        except ValueError as exc:
            errors[key] = str(exc)
            return None

    network = attempt("scan_subnet", lambda: phone_parse_network(values["scan_subnet"]))
    if network:
        hosts = network.num_addresses - 2
        hints["scan_subnet"] = (
            f"Mask {network.netmask} · usable {network.network_address + 1} - "
            f"{network.broadcast_address - 1} ({hosts} addresses)"
        )

    start = attempt("target_start", lambda: phone_parse_address(values["target_start"], network, "First phone IP"))
    end = attempt("target_end", lambda: phone_parse_address(values["target_end"], network, "Last phone IP"))
    if start:
        hints["target_start"] = str(start)
    if start and end:
        if start > end:
            errors["target_end"] = "Last phone IP must not be lower than the first phone IP."
        else:
            count = int(end) - int(start) + 1
            hints["target_end"] = f"{end} · room for {count} phone{'s' if count != 1 else ''}"
    target_range = range(int(start), int(end) + 1) if start and end and start <= end else range(0)

    gateway = attempt("gateway", lambda: phone_parse_address(values["gateway"], network, "Gateway", required=False))
    if gateway is None and network and "gateway" not in errors:
        gateway = network.broadcast_address - 1
        hints["gateway"] = f"Auto: {gateway} (last usable address)"
    elif gateway:
        hints["gateway"] = str(gateway)
    if gateway and int(gateway) in target_range:
        errors["gateway"] = f"Gateway {gateway} is inside the phone range."

    tftp = attempt("tftp_server", lambda: phone_parse_address(values["tftp_server"], network, "TFTP server"))
    if tftp:
        hints["tftp_server"] = str(tftp)
        if int(tftp) in target_range:
            errors["tftp_server"] = f"TFTP server {tftp} is inside the phone range."

    username = str(values["ssh_username"]).strip()
    if not username:
        errors["ssh_username"] = "SSH username is required."

    ssh_port = attempt("ssh_port", lambda: phone_parse_int(values["ssh_port"], "SSH port", 1, 65535))
    lease = attempt(
        "dhcp_lease_seconds", lambda: phone_parse_int(values["dhcp_lease_seconds"], "DHCP lease", 60)
    )
    dhcp_wait = attempt("dhcp_wait_seconds", lambda: phone_parse_int(values["dhcp_wait_seconds"], "DHCP wait", 10))
    probe = attempt(
        "dhcp_ssh_probe_seconds", lambda: phone_parse_int(values["dhcp_ssh_probe_seconds"], "SSH probe", 5)
    )
    ping_timeout = attempt(
        "ping_timeout_seconds", lambda: phone_parse_int(values["ping_timeout_seconds"], "Ping timeout", 5)
    )
    ping_interval = attempt(
        "ping_interval_seconds", lambda: phone_parse_int(values["ping_interval_seconds"], "Ping interval", 1)
    )

    use_dhcp = bool(values["use_dhcp_server"])
    interface = str(values["staging_interface"]).strip()
    server = pool_start = pool_end = None
    if use_dhcp:
        if not interface:
            errors["staging_interface"] = "Select the network interface the phone is connected to."
        server = attempt(
            "dhcp_server_ip",
            lambda: phone_parse_address(values["dhcp_server_ip"], network, "PC staging IP", required=False),
        )
        pool_start = attempt(
            "dhcp_pool_start",
            lambda: phone_parse_address(values["dhcp_pool_start"], network, "DHCP pool start", required=False),
        )
        pool_end = attempt(
            "dhcp_pool_end",
            lambda: phone_parse_address(values["dhcp_pool_end"], network, "DHCP pool end", required=False),
        )
        if (pool_start is None) != (pool_end is None) and not {"dhcp_pool_start", "dhcp_pool_end"} & errors.keys():
            key = "dhcp_pool_end" if pool_end is None else "dhcp_pool_start"
            errors[key] = "Fill in both pool fields, or leave both blank for auto."
        resolve_dhcp = network and target_range and gateway and tftp and not (
            {"dhcp_server_ip", "dhcp_pool_start", "dhcp_pool_end"} & errors.keys()
        )
        if resolve_dhcp:
            server, pool_start, pool_end = phone_resolve_dhcp(
                network, target_range, gateway, tftp, server, pool_start, pool_end, errors, hints
            )

    if errors:
        return None, errors, hints

    config = PhoneConfig(
        staging_interface=interface,
        scan_subnet=network,
        target_start=start,
        target_end=end,
        gateway=str(gateway),
        tftp_server=str(tftp),
        ssh_username=username,
        ssh_password=values["ssh_password"],
        ssh_port=ssh_port,
        dhcp_server_ip=server,
        dhcp_pool_start=pool_start,
        dhcp_pool_end=pool_end,
        dhcp_lease_seconds=lease,
        dhcp_wait_seconds=dhcp_wait,
        dhcp_ssh_probe_seconds=probe,
        ping_timeout_seconds=ping_timeout,
        ping_interval_seconds=ping_interval,
        use_dhcp_server=use_dhcp,
    )
    return config, errors, hints


def phone_resolve_dhcp(network, target_range, gateway, tftp, server, pool_start, pool_end, errors, hints):
    reserved = set(target_range) | {int(gateway), int(tftp)}

    if pool_start is not None and pool_start > pool_end:
        errors["dhcp_pool_end"] = "DHCP pool end must not be lower than the pool start."
        return server, pool_start, pool_end
    pool_range = range(int(pool_start), int(pool_end) + 1) if pool_start is not None else range(0)
    if pool_range and set(pool_range) & reserved:
        errors["dhcp_pool_start"] = "DHCP pool overlaps the phone range, gateway or TFTP server."
        return server, pool_start, pool_end
    if server is not None:
        if int(server) in reserved:
            errors["dhcp_server_ip"] = f"PC staging IP {server} is already used by the phone range, gateway or TFTP."
            return server, pool_start, pool_end
        if int(server) in pool_range:
            errors["dhcp_server_ip"] = f"PC staging IP {server} is inside the DHCP pool."
            return server, pool_start, pool_end

    auto_server = server is None
    auto_pool = pool_start is None
    if auto_pool:
        taken = reserved | ({int(server)} if server is not None else set())
        run = phone_longest_free_run(network, taken, 2 if auto_server else 1)
        if run is None:
            errors["dhcp_pool_start"] = "No free addresses left for a DHCP pool. Shrink the phone range."
            return server, pool_start, pool_end
        size = min(PHONE_DHCP_POOL_SIZE, run[1] - run[0] + (0 if auto_server else 1))
        pool_end = ipaddress.IPv4Address(run[1])
        pool_start = ipaddress.IPv4Address(run[1] - size + 1)
        if auto_server:
            server = pool_start - 1
    elif auto_server:
        run = phone_longest_free_run(network, reserved | set(pool_range), 1)
        if run is None:
            errors["dhcp_server_ip"] = "No free address left for the PC. Shrink the phone range or DHCP pool."
            return server, pool_start, pool_end
        server = ipaddress.IPv4Address(run[1])

    hints["dhcp_server_ip"] = f"Auto: {server}" if auto_server else str(server)
    hints["dhcp_pool_start"] = f"Auto: {pool_start}" if auto_pool else str(pool_start)
    hints["dhcp_pool_end"] = (
        f"Auto: {pool_end} ({int(pool_end) - int(pool_start) + 1} addresses)" if auto_pool else str(pool_end)
    )
    return server, pool_start, pool_end


def phone_load_settings():
    settings = dict(PHONE_CONFIG_DEFAULTS)
    settings["use_dhcp_server"] = True
    if os.path.exists(PHONE_CONFIG_SETTINGS_FILE):
        try:
            with open(PHONE_CONFIG_SETTINGS_FILE, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            for key in PHONE_CONFIG_SETTING_KEYS:
                if key in loaded:
                    settings[key] = loaded[key]
            # Older versions kept the netmask in its own field next to the subnet.
            subnet = str(settings.get("scan_subnet", "")).strip()
            if subnet and "/" not in subnet and loaded.get("netmask"):
                settings["scan_subnet"] = f"{subnet}/{loaded['netmask']}"
        except (OSError, json.JSONDecodeError):
            pass
    return settings


def phone_save_settings(settings):
    os.makedirs(APP_DATA_DIR, exist_ok=True)
    payload = {key: settings[key] for key in PHONE_CONFIG_SETTING_KEYS if key in settings}
    with open(PHONE_CONFIG_SETTINGS_FILE, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
