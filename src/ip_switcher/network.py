import ipaddress
import json

from .winutil import run_hidden, run_powershell


def subnet_mask_to_prefix(mask):
    return ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False).prefixlen


def is_bluetooth_interface(interface):
    haystack = f"{interface.get('name', '')} {interface.get('description', '')}".lower()
    return "bluetooth" in haystack


def normalize_json_list(data):
    if not data:
        return []
    if isinstance(data, list):
        return data
    return [data]


def get_interfaces_with_powershell():
    script = r"""
$ErrorActionPreference = 'Stop'
$configs = @{}
Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | ForEach-Object { $configs[$_.InterfaceIndex] = $_ }
Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.NetConnectionID } | Sort-Object NetConnectionID | ForEach-Object {
    $cfg = $configs[$_.InterfaceIndex]
    $ipv4Index = -1
    if ($cfg -and $cfg.IPAddress) {
        for ($i = 0; $i -lt $cfg.IPAddress.Count; $i++) {
            if ($cfg.IPAddress[$i] -notmatch ':') { $ipv4Index = $i; break }
        }
    }
    $ip = if ($ipv4Index -ge 0) { $cfg.IPAddress[$ipv4Index] } else { '' }
    $subnet = if ($ipv4Index -ge 0 -and $cfg.IPSubnet) { $cfg.IPSubnet[$ipv4Index] } else { '' }
    $gateway = if ($cfg -and $cfg.DefaultIPGateway) { ($cfg.DefaultIPGateway | Where-Object { $_ -notmatch ':' } | Select-Object -First 1) } else { $null }
    $statusMap = @{0='Disconnected';1='Connecting';2='Up';3='Disconnecting';4='Not Present';5='Disabled';6='Hardware malfunction';7='Disconnected';8='Authenticating';9='Authenticated';10='Auth failed';11='Invalid address';12='Credentials required'}
    $status = if (-not $_.NetEnabled) { 'Disabled' } elseif ($statusMap.ContainsKey([int]$_.NetConnectionStatus)) { $statusMap[[int]$_.NetConnectionStatus] } else { 'Unknown' }
    $speed = [uint64]$_.Speed
    $speedText = if ($speed -ge 1000000000) { '{0:N0} Gbps' -f ($speed/1000000000) } elseif ($speed -gt 0) { '{0:N0} Mbps' -f ($speed/1000000) } else { '' }
    [PSCustomObject]@{
        Name = $_.NetConnectionID
        Description = $_.Description
        Status = $status
        MacAddress = $_.MACAddress
        LinkSpeed = $speedText
        IPv4Address = $ip
        Subnet = $subnet
        Gateway = $gateway
    }
} | ConvertTo-Json -Depth 3
"""
    result = run_powershell(script)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "PowerShell failed to read adapters.")

    interfaces = [
        {
            "name": item.get("Name", ""),
            "description": item.get("Description", ""),
            "status": item.get("Status", ""),
            "mac": item.get("MacAddress", ""),
            "speed": item.get("LinkSpeed", ""),
            "ip": item.get("IPv4Address", "") or "",
            "subnet": item.get("Subnet", "") or "",
            "gateway": item.get("Gateway", "") or "",
        }
        for item in normalize_json_list(json.loads(result.stdout or "[]"))
        if item.get("Name")
    ]
    return [item for item in interfaces if not is_bluetooth_interface(item)]


def get_interfaces_with_ipconfig():
    result = run_hidden(["ipconfig"])
    if result.returncode != 0:
        raise RuntimeError("Failed to retrieve network interfaces.")

    interfaces = []
    current = {}
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if raw_line.startswith(("Ethernet adapter", "Wireless LAN adapter")):
            if current:
                interfaces.append(current)
            name = raw_line.split("adapter", 1)[1].split(":", 1)[0].strip()
            current = {
                "name": name,
                "description": "",
                "status": "",
                "mac": "",
                "speed": "",
                "ip": "",
                "subnet": "",
                "gateway": "",
            }
        elif current and "IPv4 Address" in line:
            current["ip"] = line.split(":", 1)[1].strip()
        elif current and "Subnet Mask" in line:
            current["subnet"] = line.split(":", 1)[1].strip()
        elif current and "Default Gateway" in line:
            current["gateway"] = line.split(":", 1)[1].strip()

    if current:
        interfaces.append(current)
    return [item for item in interfaces if not is_bluetooth_interface(item)]


def get_interfaces():
    try:
        return get_interfaces_with_powershell()
    except Exception:
        return get_interfaces_with_ipconfig()


def validate_ipv4(value, label, allow_empty=False):
    value = value.strip()
    if allow_empty and not value:
        return ""

    try:
        ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be a valid IPv4 address.") from exc
    return value


def validate_subnet_mask(value):
    value = validate_ipv4(value, "Subnet mask")
    try:
        ipaddress.IPv4Network(f"0.0.0.0/{value}", strict=False)
    except ValueError as exc:
        raise ValueError("Subnet mask must be a valid contiguous IPv4 mask.") from exc
    return value
