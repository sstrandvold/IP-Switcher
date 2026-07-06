# -*- mode: python ; coding: utf-8 -*-

import os
from PyInstaller.utils.hooks import collect_data_files

icon_file = os.path.abspath('icon3.ico')
version_file = os.path.abspath('file_version_info.txt')
app_version_file = os.path.abspath('VERSION')

a = Analysis(
    ['ip_switcher.py'],
    pathex=[],
    binaries=[],
    datas=collect_data_files('customtkinter') + [(icon_file, '.'), (app_version_file, '.')],
    hiddenimports=['paramiko'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    name='IP Switcher 4.5.2',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
    manifest='IP-Switcher.manifest',
    icon=icon_file,
    version=version_file,
    exclude_binaries=True,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='IP Switcher 4.5.2',
)
