import dataclasses
import ipaddress
import json
import os

from ...constants import PHONE_CONFIG_DEFAULTS, PHONE_CONFIG_SETTING_KEYS
from ...network import validate_ipv4, validate_subnet_mask
from ...paths import APP_DATA_DIR, PHONE_CONFIG_SETTINGS_FILE


@dataclasses.dataclass(frozen=True)
class PhoneConfig:
    staging_interface: str
    scan_subnet: ipaddress.IPv4Network
    target_start: ipaddress.IPv4Address
    target_end: ipaddress.IPv4Address
    netmask: str
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

    @classmethod
    def from_values(cls, values):
        config = cls(
            staging_interface=values["staging_interface"].strip(),
            scan_subnet=ipaddress.ip_network(values["scan_subnet"].strip(), strict=False),
            target_start=ipaddress.ip_address(values["target_start"].strip()),
            target_end=ipaddress.ip_address(values["target_end"].strip()),
            netmask=validate_subnet_mask(values["netmask"].strip()),
            gateway=validate_ipv4(values["gateway"].strip(), "Gateway"),
            tftp_server=validate_ipv4(values["tftp_server"].strip(), "TFTP server"),
            ssh_username=values["ssh_username"].strip(),
            ssh_password=values["ssh_password"],
            ssh_port=int(values["ssh_port"].strip()),
            dhcp_server_ip=ipaddress.ip_address(values["dhcp_server_ip"].strip()),
            dhcp_pool_start=ipaddress.ip_address(values["dhcp_pool_start"].strip()),
            dhcp_pool_end=ipaddress.ip_address(values["dhcp_pool_end"].strip()),
            dhcp_lease_seconds=int(values["dhcp_lease_seconds"].strip()),
            dhcp_wait_seconds=int(values["dhcp_wait_seconds"].strip()),
            dhcp_ssh_probe_seconds=int(values["dhcp_ssh_probe_seconds"].strip()),
            ping_timeout_seconds=int(values["ping_timeout_seconds"].strip()),
            ping_interval_seconds=int(values["ping_interval_seconds"].strip()),
            use_dhcp_server=bool(values["use_dhcp_server"]),
        )
        config.validate()
        return config

    def validate(self):
        if not self.ssh_username:
            raise ValueError("SSH username is required.")
        if self.use_dhcp_server and not self.staging_interface:
            raise ValueError("Select a network interface for the built-in DHCP server.")
        if not 1 <= self.ssh_port <= 65535:
            raise ValueError("SSH port must be between 1 and 65535.")
        if self.target_start > self.target_end:
            raise ValueError("Target start must be lower than or equal to target end.")
        if self.dhcp_pool_start > self.dhcp_pool_end:
            raise ValueError("DHCP pool start must be lower than or equal to DHCP pool end.")
        if self.dhcp_server_ip not in self.scan_subnet:
            raise ValueError("DHCP server IP must be inside the scan subnet.")
        if self.dhcp_pool_start not in self.scan_subnet or self.dhcp_pool_end not in self.scan_subnet:
            raise ValueError("DHCP pool must be inside the scan subnet.")
        dhcp_values = set(range(int(self.dhcp_pool_start), int(self.dhcp_pool_end) + 1))
        target_values = set(range(int(self.target_start), int(self.target_end) + 1))
        if dhcp_values & target_values:
            raise ValueError("DHCP pool must not overlap the target static IP range.")
        if self.dhcp_lease_seconds < 60:
            raise ValueError("DHCP lease seconds must be at least 60.")
        if self.dhcp_wait_seconds < 10:
            raise ValueError("DHCP wait seconds must be at least 10.")
        if self.dhcp_ssh_probe_seconds < 5:
            raise ValueError("DHCP SSH probe seconds must be at least 5.")
        if self.ping_timeout_seconds < 5:
            raise ValueError("Ping timeout seconds must be at least 5.")
        if self.ping_interval_seconds < 1:
            raise ValueError("Ping interval seconds must be at least 1.")


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
        except (OSError, json.JSONDecodeError):
            pass
    return settings


def phone_save_settings(settings):
    os.makedirs(APP_DATA_DIR, exist_ok=True)
    payload = {key: settings[key] for key in PHONE_CONFIG_SETTING_KEYS if key in settings}
    with open(PHONE_CONFIG_SETTINGS_FILE, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
