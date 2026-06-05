# Signing IP Switcher

Windows Defender and SmartScreen trust signed software more than unsigned software, especially when the app is distributed as a normal installer instead of a self-extracting one-file executable.

This project is set up to be safer to distribute:

- PyInstaller builds a one-folder app instead of a one-file self-extracting executable.
- UPX compression is disabled.
- The executable has company, product, version, manifest, and icon metadata.
- The Inno Setup installer installs the full app folder and creates the app data directory.

## Code Signing

The real "official" step is Authenticode signing with a code-signing certificate. You need a certificate from a trusted certificate authority. An EV certificate builds SmartScreen reputation fastest, but a standard OV certificate is still better than unsigned software.

After building, sign the executable and installer with `signtool.exe`:

```powershell
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a "src\dist\IP Switcher 4.5.1\IP Switcher 4.5.1.exe"
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a "install_file_script\installer_files\IP Switcher-4.5.1-Installer-x64.exe"
```

If you have a specific certificate thumbprint:

```powershell
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /sha1 YOUR_CERT_THUMBPRINT "src\dist\IP Switcher 4.5.1\IP Switcher 4.5.1.exe"
```

Unsigned builds may still be flagged by Defender or SmartScreen. Signing and maintaining release reputation is the durable fix.
