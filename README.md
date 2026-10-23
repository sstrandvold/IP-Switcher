# IP Switcher

IP Switcher is a small Windows GUI for changing the IPv4 configuration of network interfaces.

Version: 5.1.0

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
- Generates CODESYS PLCopen XML for DALI RIO projects, from the Tools menu. The device
  list is edited in a spreadsheet-style table, one row per RIO device, with the device's
  DALI cards as column pairs on that row. Tab or Return moves between cells, `Ctrl+V`
  pastes a block straight out of Excel, and `Ctrl+C` copies the table back out. The list
  also round-trips through CSV: *Export CSV* writes the table, or a fill-in template when
  the table is empty, and *Import CSV* reads it back. Save the XML and import it into
  CODESYS with Project > Import PLCopenXML. Project settings and the last device list are
  saved in `%APPDATA%\IP Switcher\dali-rio-settings.json`.

Earlier network monitoring tools have been removed so the app stays focused on switching
interface IP settings, plus the engineering utilities in the Tools menu.

### DALI RIO generator notes

The generator is a port of the DaliWago generator web app from `anlegg-wagoProjects`
(`Ai tools\DaliWago generator`), which remains the upstream for the generation logic. The
port keeps that code function for function so upstream fixes carry over, and swaps lxml
for `xml.etree.ElementTree` so the app ships without a C extension. The CODESYS template
project travels inline as a gzip and base64 blob in `template_b64.py`, so the tool needs
no data files at runtime.

The controller (PLC) is a per-project setting rather than a property of the template. Pick
one with *Select PLC…*, which lists the PLC device descriptions installed in the local
CODESYS device repositories (`%ProgramData%\CODESYS*\Devices\4096`), or type the device
type, ID and version by hand for a machine other than this one. The defaults are the
750-8001 WAGO Basic Controller 100 that the template was built around.

The panel says which CODESYS versions have the selected device, because this is the most
likely reason an import fails:

```
The PLCopenXML import is not possible because Device not found.
Type: 4096, ID: 1006 8007, Version: 1.2.0.6.
```

CODESYS matches a device on type, ID and version exactly, and refuses the entire import
when no installed description matches - without saying which instance it searched. The fix
is to install the vendor package into the CODESYS instance doing the import, or to select a
PLC that instance already has. Note that swapping the controller rewrites its identity
only: the Kbus still attaches through the `Wago.LocalBus` connector inherited from the
template, so the tool warns when the chosen device does not offer that connector.

The CSV is written semicolon-delimited as UTF-8 with a BOM, which is what opens straight
into columns in Norwegian Excel rather than triggering the text import wizard. Import is
more forgiving: it sniffs comma, semicolon and tab delimiters, and reads both UTF-8 and the
cp1252 that Excel's plain "CSV (Comma delimited)" option produces.

Two things to know before changing `xml_builder.py`:

- The document mixes the PLCopen default namespace with deliberately un-namespaced
  islands (the FBD graphics and the ModbusTCP `Device` configs). `xmlns=""` is declared
  by hand exactly where it belongs, and `restore_parsed_ns_islands` puts back the
  declarations that parsing the template discards. Dropping either silently moves whole
  subtrees into the PLCopen namespace, which CODESYS will reject only at import time.
- One SA module addresses at most four DALI cards, since `SLOT_PARAMS` holds four slot
  address entries.

Output is verified by generating the same projects with the upstream lxml code and
comparing the two trees structurally. Namespace prefix spelling differs harmlessly
between the backends, so compare re-parsed trees in `{uri}local` form rather than
canonical XML text. Changes to the generator should be re-checked that way, and then by
importing the result into CODESYS V3.5 SP19 and confirming a clean F11 build.

## Build

Install dependencies first:

```powershell
python -m pip install -r requirements.txt
```

Then build from `src`:

```powershell
pyinstaller IP-Switcher.spec
```

The build outputs a one-folder app at `src/dist/IP Switcher 5.1.0/`. The executable requests administrator privileges because changing interface IP settings requires elevation on Windows.

## Installer and Signing

The app does not need an installer for Python dependencies because they are bundled by PyInstaller. The installer is still recommended for a more official Windows experience: install location, Start Menu shortcut, uninstall entry, icon metadata, and app data directory creation.

The project intentionally builds a one-folder app with UPX disabled because that is less suspicious to antivirus tools than a one-file self-extracting executable. For best Defender and SmartScreen behavior, sign the executable and installer with an Authenticode code-signing certificate. See `SIGNING.md`.
