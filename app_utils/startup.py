from __future__ import annotations

import base64
import os
import subprocess
import sys
from pathlib import Path

from app_utils.logger import logger
from app_utils.paths import APP_DISPLAY_NAME, APP_NAME


BACKGROUND_ARG = "--background"


def is_background_launch(argv: list[str] | None = None) -> bool:
    args = sys.argv[1:] if argv is None else argv
    return BACKGROUND_ARG in args


def build_background_launch_command() -> tuple[str, str, str]:
    if getattr(sys, "frozen", False):
        executable = str(Path(sys.executable).resolve(strict=False))
        arguments = BACKGROUND_ARG
        working_dir = str(Path(executable).parent)
        return executable, arguments, working_dir

    executable = _preferred_pythonw()
    script_path = str(Path(__file__).resolve().parent.parent / "main.py")
    arguments = subprocess.list2cmdline([script_path, BACKGROUND_ARG])
    working_dir = str(Path(script_path).parent)
    return executable, arguments, working_dir


def ensure_startup_shortcut() -> bool:
    if os.name != "nt":
        return False

    executable, arguments, working_dir = build_background_launch_command()
    shortcut_name = f"{APP_DISPLAY_NAME}.lnk"
    task_name = f"{APP_NAME}_Startup"
    script = f"""
$ErrorActionPreference = 'Stop'
$action = New-ScheduledTaskAction -Execute '{_escape_powershell_single_quoted(executable)}' -Argument '{_escape_powershell_single_quoted(arguments)}' -WorkingDirectory '{_escape_powershell_single_quoted(working_dir)}'
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0
Register-ScheduledTask -TaskName '{_escape_powershell_single_quoted(task_name)}' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force

$startup = [Environment]::GetFolderPath('Startup')
if ($startup) {{
    $oldShortcut = Join-Path $startup '{_escape_powershell_single_quoted(shortcut_name)}'
    if (Test-Path $oldShortcut) {{
        Remove-Item $oldShortcut -Force
    }}
}}
"""

    try:
        encoded_script = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        subprocess.run(
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
            check=True,
            timeout=15,
        )
        logger.info("Startup shortcut is enabled for %s.", APP_NAME)
        return True
    except Exception as exc:
        logger.warning("Failed to create startup shortcut: %s", exc)
        return False


def ensure_start_menu_shortcut() -> bool:
    if os.name != "nt":
        return False

    if getattr(sys, "frozen", False):
        executable = str(Path(sys.executable).resolve(strict=False))
        arguments = ""
        working_dir = str(Path(executable).parent)
    else:
        executable = _preferred_pythonw()
        script_path = str(Path(__file__).resolve().parent.parent / "main.py")
        arguments = subprocess.list2cmdline([script_path])
        working_dir = str(Path(script_path).parent)

    shortcut_name = f"{APP_DISPLAY_NAME}.lnk"
    description = f"Open {APP_DISPLAY_NAME}"
    script = f"""
$ErrorActionPreference = 'Stop'
$programs = [Environment]::GetFolderPath('Programs')
if (-not $programs) {{ throw 'Start Menu Programs folder not found.' }}
$shortcutPath = Join-Path $programs '{_escape_powershell_single_quoted(shortcut_name)}'
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = '{_escape_powershell_single_quoted(executable)}'
$shortcut.Arguments = '{_escape_powershell_single_quoted(arguments)}'
$shortcut.WorkingDirectory = '{_escape_powershell_single_quoted(working_dir)}'
$shortcut.IconLocation = '{_escape_powershell_single_quoted(executable)},0'
$shortcut.Description = '{_escape_powershell_single_quoted(description)}'
$shortcut.Save()
"""

    try:
        encoded_script = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        subprocess.run(
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
            check=True,
            timeout=15,
        )
        return True
    except Exception as exc:
        logger.warning("Failed to create start menu shortcut: %s", exc)
        return False


def _preferred_pythonw() -> str:
    executable = Path(sys.executable).resolve(strict=False)
    pythonw = executable.with_name("pythonw.exe")
    if pythonw.is_file():
        return str(pythonw)
    return str(executable)


def _escape_powershell_single_quoted(value: str) -> str:
    return str(value).replace("'", "''")
