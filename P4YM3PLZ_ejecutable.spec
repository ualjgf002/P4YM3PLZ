# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['c:\\Users\\ual\\P4YM3PLZ\\P4YM3PLZ\\Programa\\ejecutable.py'],
    pathex=[],
    binaries=[],
    datas=[('rsa_main_public.pem', '.'), ('rsa_two_public.pem', '.'), ('rsa_special_public.pem', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='P4YM3PLZ_ram',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
