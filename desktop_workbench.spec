from pathlib import Path

root = Path(SPECPATH).resolve()
theme = root / "desktop" / "resources" / "theme.qss"

a = Analysis(
    [str(root / "desktop" / "__main__.py")],
    pathex=[str(root)],
    binaries=[],
    datas=[(str(theme), "desktop/resources")],
    hiddenimports=[],
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
    exclude_binaries=True,
    name="BugBountyWorkbench",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="BugBountyWorkbench",
)
