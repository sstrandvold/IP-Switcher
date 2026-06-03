# IP Switcher

IP Switcher is a small Windows GUI for changing the IPv4 configuration of network interfaces.

Version: 4.4.0

## What It Does

- Lists Windows network interfaces and their current IPv4 details.
- Applies a static IP address, subnet mask, and optional gateway with `netsh`.
- Switches a selected interface back to DHCP.
- Saves reusable IP presets named like `192.168.1.1/24` in `%APPDATA%\IP Switcher\presets.json`.
- Imports and exports preset JSON files.

Earlier network monitoring tools have been removed so the app stays focused on switching interface IP settings.

## Build

Install dependencies first:

```powershell
python -m pip install -r requirements.txt
```

Then build from `src`:

```powershell
pyinstaller IP-Switcher.spec
```

The executable requests administrator privileges because changing interface IP settings requires elevation on Windows.
