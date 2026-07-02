# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
import sys

python_base = Path(sys.base_prefix)
python_dlls = python_base / 'DLLs'
python_tcl = python_base / 'tcl'

tk_binaries = [
    (str(path), '.')
    for path in (
        python_dlls / '_tkinter.pyd',
        python_dlls / 'tcl86t.dll',
        python_dlls / 'tk86t.dll',
    )
    if path.exists()
]

tk_datas = [
    (str(source), target)
    for source, target in (
        (python_base / 'Lib' / 'tkinter', 'tkinter'),
        (python_tcl / 'tcl8.6', '_tcl_data'),
        (python_tcl / 'tk8.6', '_tk_data'),
    )
    if source.exists()
]


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=tk_binaries,
    datas=[
        ('assets\\dashboard_logo.png', 'assets'),
        ('assets\\dashboard_logo.ico', 'assets'),
        ('assets\\app_icon.png', 'assets'),
        ('assets\\app_icon.ico', 'assets'),
        *tk_datas,
    ],
    hiddenimports=[
        '_tkinter',
        'tkinter',
        'tkinter.filedialog',
        'tkinter.messagebox',
        'tkinter.ttk',
    ],
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
    name='ZenvorLock',
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
    version='version_info.txt',
    icon='assets\\app_icon.ico',
)
