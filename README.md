# IP Switcher

IP Switcher is a small Windows GUI for changing the IPv4 configuration of network interfaces.

Version: 4.4.1

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

The build outputs a one-folder app at `src/dist/IP Switcher 4.4.1/`. The executable requests administrator privileges because changing interface IP settings requires elevation on Windows.

## Installer and Signing

The app does not need an installer for Python dependencies because they are bundled by PyInstaller. The installer is still recommended for a more official Windows experience: install location, Start Menu shortcut, uninstall entry, icon metadata, and app data directory creation.

The project intentionally builds a one-folder app with UPX disabled because that is less suspicious to antivirus tools than a one-file self-extracting executable. For best Defender and SmartScreen behavior, sign the executable and installer with an Authenticode code-signing certificate. See `SIGNING.md`.
