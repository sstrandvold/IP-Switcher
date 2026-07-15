# IP Switcher

IP Switcher is a small Windows GUI for changing the IPv4 configuration of network interfaces.

Version: 5.0.1

## What It Does

- Lists Windows network interfaces and their current IPv4 details.
- Applies a static IP address, subnet mask, and optional gateway with `netsh`.
- Switches a selected interface back to DHCP.
- Saves reusable IP presets named like `192.168.1.1/24` in `%APPDATA%\IP Switcher\presets.json`.
- Imports and exports preset JSON files.
- Generates importable MTPuTTY XML trees from `multiping.txt` files.
- Configures SSH-capable IP phones from the Tools menu with DHCP staging,
  static IP assignment, TFTP settings, ping, and SSH read-back verification.
  Phone assignment history is written to `%APPDATA%\IP Switcher\phone-configurator-log.csv`
  and can be viewed or opened from the phone configurator window. Phone tool
  settings are saved in `%APPDATA%\IP Switcher\phone-configurator-settings.json`.
  The phone tool can select the host network interface and set it to the DHCP
  server IP automatically before starting the built-in DHCP server. It also
  probes the selected interface for existing DHCP servers and blocks startup if
  another server responds.

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

The build outputs a one-folder app at `src/dist/IP Switcher 5.0.1/`. The executable requests administrator privileges because changing interface IP settings requires elevation on Windows.

## Installer and Signing

The app does not need an installer for Python dependencies because they are bundled by PyInstaller. The installer is still recommended for a more official Windows experience: install location, Start Menu shortcut, uninstall entry, icon metadata, and app data directory creation.

The project intentionally builds a one-folder app with UPX disabled because that is less suspicious to antivirus tools than a one-file self-extracting executable. For best Defender and SmartScreen behavior, sign the executable and installer with an Authenticode code-signing certificate. See `SIGNING.md`.
