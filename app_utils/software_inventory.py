from __future__ import annotations

import base64
import json
import os
import re
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable
import winreg

WINDOWS_UNINSTALL_LOCATIONS = (
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
)

START_MENU_DIRS = (
    Path(os.environ.get("ProgramData", ""))
    / "Microsoft"
    / "Windows"
    / "Start Menu"
    / "Programs",
    Path(os.environ.get("APPDATA", ""))
    / "Microsoft"
    / "Windows"
    / "Start Menu"
    / "Programs",
    Path(os.environ.get("PUBLIC", "")) / "Desktop",
    Path(os.environ.get("USERPROFILE", "")) / "Desktop",
)

IGNORED_TOKENS = {
    "uninstall",
    "unins",
}

ICON_FILE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".ico",
    ".icl",
    ".cpl",
    ".mun",
}


@dataclass(frozen=True)
class InventoryApp:
    display_name: str
    executable_name: str
    path: str
    icon_path: str = ""
    is_locked: bool = False
    sources: tuple[str, ...] = ()

    @property
    def status(self) -> str:
        return "Locked" if self.is_locked else "Unlocked"

    @property
    def dedupe_key(self) -> str:
        normalized_path = normalize_path(self.path)
        if normalized_path:
            return normalized_path
        return (self.executable_name or self.display_name).casefold()


def _get_long_path_name(path: str) -> str:
    try:
        import ctypes
        from ctypes import wintypes

        buf_size = 260
        buf = ctypes.create_unicode_buffer(buf_size)
        result = ctypes.windll.kernel32.GetLongPathNameW(path, buf, buf_size)
        if result > 0 and result <= buf_size:
            return buf.value
    except Exception:
        pass
    return path


def normalize_path(path: str | os.PathLike[str] | None) -> str:
    if not path:
        return ""

    value = str(path).strip().strip('"').strip()
    if not value:
        return ""

    value = os.path.expanduser(os.path.expandvars(value))
    normalized = os.path.normpath(value)
    abspath = os.path.abspath(normalized)
    if os.name == "nt":
        abspath = _get_long_path_name(abspath)
    return abspath


def is_valid_executable(path: str | os.PathLike[str] | None) -> bool:
    normalized = normalize_path(path)
    if not normalized:
        return False
    if not normalized.lower().endswith(".exe"):
        return False
    if not os.path.isfile(normalized):
        return False
    return not contains_ignored_token(normalized)


def is_valid_icon_source(path: str | os.PathLike[str] | None) -> bool:
    normalized = normalize_path(path)
    if not normalized:
        return False
    if not os.path.isfile(normalized):
        return False
    return Path(normalized).suffix.casefold() in ICON_FILE_EXTENSIONS


def contains_ignored_token(value: str | None) -> bool:
    if not value:
        return False
    lowered = value.casefold()
    return any(token in lowered for token in IGNORED_TOKENS)


def extract_executable_name(path_or_name: str | None, fallback: str = "") -> str:
    if not path_or_name:
        return fallback.strip()

    candidate = str(path_or_name).strip().strip('"')
    if not candidate:
        return fallback.strip()

    if candidate.lower().endswith(".exe"):
        return os.path.basename(candidate)

    if os.path.sep in candidate or "/" in candidate:
        basename = os.path.basename(candidate)
        if basename:
            return basename

    if ".exe" in candidate.lower():
        match = re.search(r"([^\\/:\"']+?\.exe)", candidate, flags=re.IGNORECASE)
        if match:
            return match.group(1)

    fallback = fallback.strip()
    return fallback or candidate


def build_software_inventory(locked_apps: Iterable[object]) -> list[InventoryApp]:
    discovered = _deduplicate_records(
        [
            *_scan_registry_for_software(),
            *_scan_start_menu_shortcuts(),
            *_scan_uwp_apps(),
        ]
    )
    merged = _merge_locked_apps(discovered, locked_apps)
    return sorted(
        merged,
        key=lambda app: (
            0 if app.is_locked else 1,
            app.display_name.casefold(),
            app.executable_name.casefold(),
            normalize_path(app.path).casefold(),
        ),
    )


def _scan_registry_for_software() -> list[InventoryApp]:
    records: list[InventoryApp] = []

    for hive, uninstall_path in WINDOWS_UNINSTALL_LOCATIONS:
        try:
            with winreg.OpenKey(hive, uninstall_path) as uninstall_key:
                subkey_count = winreg.QueryInfoKey(uninstall_key)[0]
                for index in range(subkey_count):
                    try:
                        subkey_name = winreg.EnumKey(uninstall_key, index)
                        with winreg.OpenKey(uninstall_key, subkey_name) as app_key:
                            record = _build_registry_record(app_key)
                            if record is not None:
                                records.append(record)
                    except OSError:
                        continue
        except OSError:
            continue

    return records


def _scan_start_menu_shortcuts() -> list[InventoryApp]:
    roots = [str(path) for path in START_MENU_DIRS if str(path) and path.exists()]
    if not roots:
        return []

    script = rf"""
$ErrorActionPreference = 'SilentlyContinue'
$roots = ConvertFrom-Json @'
{json.dumps(roots)}
'@
$shell = New-Object -ComObject WScript.Shell
$results = foreach ($root in $roots) {{
    if (-not (Test-Path $root)) {{
        continue
    }}

    Get-ChildItem -Path $root -Filter *.lnk -Recurse -File | ForEach-Object {{
        try {{
            $shortcut = $shell.CreateShortcut($_.FullName)
            [PSCustomObject]@{{
                shortcut = $_.FullName
                name = $_.BaseName
                target = $shortcut.TargetPath
                icon = $shortcut.IconLocation
            }}
        }} catch {{
        }}
    }}
}}

if ($results) {{
    $results | ConvertTo-Json -Compress
}}
"""

    result = _run_powershell_json(script, timeout=20)
    if result is None:
        return []

    payload = result.stdout.strip()
    if not payload:
        return []

    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        return []

    if isinstance(parsed, dict):
        items = [parsed]
    else:
        items = [item for item in parsed if isinstance(item, dict)]

    records: list[InventoryApp] = []
    for item in items:
        target = _first_valid_path(item.get("target", ""))
        if not target:
            continue

        shortcut_name = _clean_display_name(item.get("name", ""))
        executable_name = extract_executable_name(target)
        display_name = shortcut_name or Path(target).stem or executable_name
        icon_path = _first_valid_icon_path(item.get("icon", ""), target)

        if contains_ignored_token(display_name) or contains_ignored_token(
            executable_name
        ):
            continue

        records.append(
            InventoryApp(
                display_name=display_name,
                executable_name=executable_name,
                path=target,
                icon_path=icon_path or target,
                sources=("start_menu",),
            )
        )

    return records


def _scan_uwp_apps() -> list[InventoryApp]:
    script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$packages = Get-AppxPackage | Where-Object { $_.IsFramework -eq $false -and $_.NonRemovable -eq $false }
$results = foreach ($pkg in $packages) {
    try {
        $manifest = [xml](Get-AppxPackageManifest -Package $pkg.PackageFullName)
        $appName = $manifest.Package.Properties.DisplayName
        if (-not $appName) { $appName = $pkg.Name }
        
        $app = $manifest.Package.Applications.Application
        $exe = $null
        if ($app -is [array]) { $exe = $app[0].Executable } else { $exe = $app.Executable }
        
        if ($exe -and $pkg.InstallLocation) {
            $fullPath = Join-Path $pkg.InstallLocation $exe
            
            $iconPath = $fullPath
            $logo = $manifest.Package.Properties.Logo
            if ($logo) {
                $logoBase = [System.IO.Path]::GetFileNameWithoutExtension($logo)
                $logoDir = Join-Path $pkg.InstallLocation ([System.IO.Path]::GetDirectoryName($logo))
                $foundLogos = Get-ChildItem -Path $logoDir -Filter "$logoBase*.png" -ErrorAction SilentlyContinue
                if ($foundLogos) {
                    $iconPath = $foundLogos[0].FullName
                }
            }
            
            [PSCustomObject]@{
                name = $appName
                executable = $exe
                target = $fullPath
                icon = $iconPath
            }
        }
    } catch {}
}
if ($results) {
    $results | ConvertTo-Json -Compress
}
"""
    result = _run_powershell_json(script, timeout=20)
    if result is None:
        return []

    payload = result.stdout.strip()
    if not payload:
        return []

    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        return []

    if isinstance(parsed, dict):
        items = [parsed]
    else:
        items = [item for item in parsed if isinstance(item, dict)]

    records: list[InventoryApp] = []
    for item in items:
        target = item.get("target", "")
        if not target or not is_valid_executable(target):
            continue

        display_name = item.get("name", "")
        # Resolve 'ms-resource:' names for UWP apps
        if display_name.startswith("ms-resource:"):
            display_name = Path(target).stem

        executable_name = item.get("executable", "")
        if contains_ignored_token(display_name) or contains_ignored_token(
            executable_name
        ):
            continue

        records.append(
            InventoryApp(
                display_name=display_name,
                executable_name=executable_name,
                path=target,
                icon_path=item.get("icon", target),
                sources=("uwp",),
            )
        )
    return records


def _build_registry_record(app_key) -> InventoryApp | None:
    display_name = _clean_display_name(_safe_reg_value(app_key, "DisplayName"))
    if not display_name or contains_ignored_token(display_name):
        return None

    display_icon_value = _safe_reg_value(app_key, "DisplayIcon")
    display_icon_path = _first_valid_path(display_icon_value)
    icon_path = _first_valid_icon_path(display_icon_value)
    install_location_path = _find_executable_in_install_location(
        _safe_reg_value(app_key, "InstallLocation"),
        display_name,
    )
    uninstall_path = _first_valid_path(
        _safe_reg_value(app_key, "QuietUninstallString"),
        _safe_reg_value(app_key, "UninstallString"),
    )

    candidate_path = ""
    for path_candidate in (display_icon_path, install_location_path, uninstall_path):
        if path_candidate and _is_related_executable(display_name, path_candidate):
            candidate_path = path_candidate
            break

    if not candidate_path:
        for path_candidate in (
            display_icon_path,
            install_location_path,
            uninstall_path,
        ):
            if path_candidate:
                candidate_path = path_candidate
                break

    executable_hint = _first_executable_name(
        _safe_reg_value(app_key, "DisplayIcon"),
        _safe_reg_value(app_key, "QuietUninstallString"),
        _safe_reg_value(app_key, "UninstallString"),
    )
    executable_name = extract_executable_name(
        candidate_path,
        fallback=executable_hint or display_name,
    )

    if contains_ignored_token(executable_name):
        return None

    return InventoryApp(
        display_name=display_name,
        executable_name=executable_name,
        path=candidate_path,
        icon_path=icon_path or candidate_path,
        sources=("registry",),
    )


def _first_valid_path(*values: str) -> str:
    for value in values:
        for candidate in _extract_executable_candidates(value):
            if is_valid_executable(candidate):
                return normalize_path(candidate)
    return ""


def _first_valid_icon_path(*values: str) -> str:
    for value in values:
        for candidate in _extract_icon_candidates(value):
            if is_valid_icon_source(candidate):
                return normalize_path(candidate)
    return ""


def _extract_executable_candidates(value: str | None) -> list[str]:
    if not value:
        return []

    text = str(value).strip()
    if not text:
        return []

    matches: list[str] = []
    for quoted in re.findall(r'"([^"]+?\.exe)"', text, flags=re.IGNORECASE):
        matches.append(quoted)

    for raw in re.findall(r"([A-Za-z]:\\[^,\r\n]+?\.exe)", text, flags=re.IGNORECASE):
        matches.append(raw)

    if text.lower().endswith(".exe"):
        matches.append(text)

    cleaned: list[str] = []
    seen: set[str] = set()
    for match in matches:
        candidate = normalize_path(match)
        if not candidate:
            continue
        lowered = candidate.casefold()
        if lowered in seen:
            continue
        seen.add(lowered)
        cleaned.append(candidate)
    return cleaned


def _extract_icon_candidates(value: str | None) -> list[str]:
    if not value:
        return []

    text = str(value).strip()
    if not text:
        return []

    extension_pattern = "|".join(
        ext.lstrip(".") for ext in sorted(ICON_FILE_EXTENSIONS)
    )
    matches: list[str] = []

    quoted_pattern = rf'"([^"]+?\.(?:{extension_pattern}))"'
    raw_pattern = rf"([A-Za-z]:\\[^,\r\n]+?\.(?:{extension_pattern}))"

    for quoted in re.findall(quoted_pattern, text, flags=re.IGNORECASE):
        matches.append(quoted)

    for raw in re.findall(raw_pattern, text, flags=re.IGNORECASE):
        matches.append(raw)

    if Path(text).suffix.casefold() in ICON_FILE_EXTENSIONS:
        matches.append(text)

    cleaned: list[str] = []
    seen: set[str] = set()
    for match in matches:
        candidate = normalize_path(match)
        if not candidate:
            continue
        lowered = candidate.casefold()
        if lowered in seen:
            continue
        seen.add(lowered)
        cleaned.append(candidate)
    return cleaned


def _first_executable_name(*values: str) -> str:
    for value in values:
        candidates = _extract_executable_candidates(value)
        if candidates:
            return os.path.basename(candidates[0])
    return ""


def _find_executable_in_install_location(
    value: str | None, display_name: str = ""
) -> str:
    if not value:
        return ""

    candidate_dir = normalize_path(value)
    if not candidate_dir or not os.path.isdir(candidate_dir):
        return ""

    executables = [
        path
        for path in Path(candidate_dir).glob("*.exe")
        if path.is_file() and not contains_ignored_token(str(path))
    ]

    if not executables:
        return ""

    executables.sort(
        key=lambda path: _install_location_score(path, display_name),
        reverse=True,
    )
    return normalize_path(executables[0])


def _install_location_score(path: Path, display_name: str) -> tuple[int, int, int]:
    stem = path.stem.casefold()
    display_tokens = _tokenize_display_name(display_name)
    token_matches = sum(1 for token in display_tokens if token in stem)
    exactish_match = 1 if stem.replace(" ", "") == "".join(display_tokens) else 0
    filename_length = len(path.name)
    return (token_matches, exactish_match, filename_length)


def _tokenize_display_name(display_name: str) -> list[str]:
    return [
        token
        for token in re.findall(r"[a-z0-9]+", display_name.casefold())
        if len(token) > 1
    ]


def _is_related_executable(display_name: str, executable_path: str) -> bool:
    if not executable_path:
        return False

    display_tokens = _tokenize_display_name(display_name)
    if not display_tokens:
        return True

    executable_stem = Path(executable_path).stem.casefold()
    token_matches = sum(1 for token in display_tokens if token in executable_stem)
    condensed_name = "".join(display_tokens)
    return token_matches > 0 or executable_stem.replace(" ", "") == condensed_name


def _safe_reg_value(app_key, value_name: str) -> str:
    try:
        value, _ = winreg.QueryValueEx(app_key, value_name)
    except OSError:
        return ""

    if value is None:
        return ""
    return str(value).strip()


def _run_powershell_json(
    script: str, *, timeout: int
) -> subprocess.CompletedProcess[str] | None:
    encoded_script = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    try:
        return subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                encoded_script,
            ],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _clean_display_name(value: str | None) -> str:
    if not value:
        return ""
    cleaned = " ".join(str(value).strip().split())
    return cleaned


def _deduplicate_records(records: Iterable[InventoryApp]) -> list[InventoryApp]:
    by_path: dict[str, InventoryApp] = {}
    by_name: dict[str, InventoryApp] = {}

    for record in records:
        if contains_ignored_token(record.display_name) or contains_ignored_token(
            record.executable_name
        ):
            continue

        normalized_path = normalize_path(record.path)
        if normalized_path:
            current = by_path.get(normalized_path.casefold())
            merged = _merge_inventory_records(
                current, replace(record, path=normalized_path)
            )
            by_path[normalized_path.casefold()] = merged
            continue

        name_key = (record.executable_name or record.display_name).casefold()
        if not name_key:
            continue
        current = by_name.get(name_key)
        by_name[name_key] = _merge_inventory_records(current, record)

    return [*by_path.values(), *by_name.values()]


def _merge_inventory_records(
    current: InventoryApp | None,
    incoming: InventoryApp,
) -> InventoryApp:
    if current is None:
        return incoming

    display_name = _pick_better_display_name(current, incoming)
    executable_name = incoming.executable_name or current.executable_name
    path = incoming.path or current.path
    icon_path = incoming.icon_path or current.icon_path or path
    is_locked = current.is_locked or incoming.is_locked
    sources = tuple(sorted(set(current.sources + incoming.sources)))

    return InventoryApp(
        display_name=display_name,
        executable_name=executable_name,
        path=path,
        icon_path=icon_path,
        is_locked=is_locked,
        sources=sources,
    )


def _pick_better_display_name(current: InventoryApp, incoming: InventoryApp) -> str:
    current_name = current.display_name.strip()
    incoming_name = incoming.display_name.strip()

    current_score = _display_name_score(current_name, current.executable_name)
    incoming_score = _display_name_score(incoming_name, incoming.executable_name)

    if incoming_score > current_score:
        return incoming_name
    return current_name or incoming_name


def _display_name_score(display_name: str, executable_name: str) -> tuple[int, int]:
    if not display_name:
        return (0, 0)

    stem = Path(executable_name).stem.casefold() if executable_name else ""
    normalized_name = display_name.casefold()
    human_friendly = 0 if stem and normalized_name == stem else 1
    return (human_friendly, len(display_name))


def _merge_locked_apps(
    discovered: list[InventoryApp],
    locked_apps: Iterable[object],
) -> list[InventoryApp]:
    by_path: dict[str, InventoryApp] = {}
    by_name: dict[str, InventoryApp] = {}

    for app in discovered:
        normalized_path = normalize_path(app.path)
        if normalized_path:
            by_path[normalized_path.casefold()] = app
        name_key = (app.executable_name or app.display_name).casefold()
        if name_key:
            by_name[name_key] = app

    merged: dict[str, InventoryApp] = {
        app.dedupe_key.casefold(): app for app in discovered
    }

    for locked_app in locked_apps:
        app_name = _locked_value(locked_app, "app_name")
        app_path = normalize_path(_locked_value(locked_app, "app_path"))
        lookup_key = app_path.casefold() if app_path else app_name.casefold()

        matched: InventoryApp | None = None
        if app_path:
            matched = by_path.get(app_path.casefold())
        if matched is None and app_name:
            matched = by_name.get(app_name.casefold())

        if matched is not None:
            merged[matched.dedupe_key.casefold()] = replace(matched, is_locked=True)
            continue

        executable_name = extract_executable_name(app_path, fallback=app_name)
        display_name = Path(app_path).stem if app_path else app_name
        display_name = display_name or executable_name or "Unknown Application"

        merged[lookup_key] = InventoryApp(
            display_name=display_name,
            executable_name=executable_name or app_name or display_name,
            path=app_path,
            icon_path=app_path,
            is_locked=True,
            sources=("locked_db",),
        )

    return list(merged.values())


def _locked_value(locked_app: object, field_name: str) -> str:
    if isinstance(locked_app, dict):
        value = locked_app.get(field_name, "")
    else:
        value = getattr(locked_app, field_name, "")
    return str(value or "").strip()
