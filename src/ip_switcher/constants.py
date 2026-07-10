import subprocess

APP_NAME = "IP Switcher"
ORG_NAME = "Trafsys AS"
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
DWMWA_USE_IMMERSIVE_DARK_MODE = 20
DWMWA_USE_IMMERSIVE_DARK_MODE_OLD = 19
DWMWA_BORDER_COLOR = 34
DWMWA_CAPTION_COLOR = 35
DWMWA_TEXT_COLOR = 36
DARK_BORDER_COLOR = 0x00221B15
DARK_CAPTION_COLOR = 0x00221B15
LIGHT_TEXT_COLOR = 0x00FCFAF7

MTPUTTY_PASSWORD_TOKEN = "peziKED81ZUhG8W1I57eIr+AawG6+rvG"
MTPUTTY_COMMAND_OPTIONS = [
    ("Enable", "enable"),
    ("Configure terminal", "conf term"),
    ("Terminal length 0", "terminal length 0"),
    ("Show running config", "show running-config"),
]

PHONE_CONFIG_DEFAULTS = {
    "staging_interface": "",
    "scan_subnet": "10.32.139.0/24",
    "target_start": "10.32.139.175",
    "target_end": "10.32.139.184",
    "netmask": "255.255.255.0",
    "gateway": "10.32.139.254",
    "tftp_server": "10.32.139.150",
    "ssh_username": "root",
    "ssh_password": "n0cerr1er",
    "ssh_port": "22",
    "dhcp_server_ip": "10.32.139.5",
    "dhcp_pool_start": "10.32.139.21",
    "dhcp_pool_end": "10.32.139.50",
    "dhcp_lease_seconds": "600",
    "dhcp_wait_seconds": "180",
    "dhcp_ssh_probe_seconds": "30",
    "ping_timeout_seconds": "180",
    "ping_interval_seconds": "2",
}
PHONE_CONFIG_SETTING_KEYS = list(PHONE_CONFIG_DEFAULTS.keys()) + ["use_dhcp_server"]
PHONE_CONFIG_LOG_FIELDS = [
    "timestamp",
    "mac",
    "dhcp_ip",
    "target_ip",
    "netmask",
    "gateway",
    "tftp_server",
    "status",
    "message",
]
