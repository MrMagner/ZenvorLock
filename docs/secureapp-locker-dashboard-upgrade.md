# SecureApp Locker Dashboard Upgrade

## Executive Summary

SecureApp Locker has been upgraded from a manual `locked_apps` list into a unified installed-software inventory and lock management dashboard.

The implementation now:

- Discovers installed Windows software from uninstall registry keys, Start Menu shortcuts, and the existing `locked_apps` database.
- Merges discovered software with locked state into a single searchable inventory.
- Displays locked applications first, unlocked applications second, and sorts alphabetically inside each group.
- Supports multi-select lock and unlock actions gated by the existing master password.
- Preserves the monitor and controller flow while improving enforcement precision with executable-path matching.
- Hardens the SQLite layer with migration-safe deduplication, uniqueness indexes, and serialized write transactions.

This document maps directly to the current implementation in the repository.

## Phase Roadmap

### Phase 1: Data and Persistence

- Upgrade database initialization to support write locking and migration-safe indexes.
- Deduplicate legacy `locked_apps` rows before uniqueness rules are enforced.
- Centralize lock/unlock operations behind a repository API.

### Phase 2: Software Discovery

- Add `app_utils/software_inventory.py`.
- Discover software from:
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
  - `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
  - `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
  - Common and per-user Start Menu shortcut trees
  - Existing locked-app records
- Normalize valid `.exe` paths, ignore updaters and uninstallers, and fall back cleanly when the path is unavailable.

### Phase 3: Dashboard Upgrade

- Replace the legacy locked-list view with a Treeview inventory.
- Add search, refresh, lock selected, and unlock selected actions.
- Keep UI updates responsive by performing discovery on a background thread and marshaling results back through a queue.

### Phase 4: Enforcement and Release Hardening

- Improve monitor matching from `app_name`-only to `app_path`-first with `app_name` fallback.
- Preserve the intercept prompt and launch flow.
- Add build, smoke-test, packaging, and deployment guidance.

## Implemented Folder Structure

```text
SecureApp Locker/
|-- app_utils/
|   |-- locked_apps_repository.py
|   |-- logger.py
|   |-- paths.py
|   `-- software_inventory.py
|-- config/
|   `-- config_manager.py
|-- monitoring/
|   `-- process_monitor.py
|-- security/
|   `-- auth_manager.py
|-- ui/
|   |-- dashboard.py
|   `-- password_prompt.py
|-- docs/
|   `-- secureapp-locker-dashboard-upgrade.md
|-- controller.py
|-- main.py
`-- SecureAppLocker.spec
```

## Architecture Overview

### Runtime Layers

1. `software_inventory.py`
   Builds the unified installed-software inventory from Windows sources.

2. `locked_apps_repository.py`
   Encapsulates all lock-state reads and writes.

3. `dashboard.py`
   Presents merged inventory state and initiates password-gated lock changes.

4. `process_monitor.py`
   Continuously scans running processes and blocks locked targets.

5. `controller.py`
   Coordinates monitor events, authentication prompts, and approved relaunches.

### Design Principles

- Preserve current product behavior where possible.
- Keep all security-sensitive state changes password-gated.
- Use path-based identity when available because executable names are not globally unique.
- Prefer conservative discovery over attaching the wrong executable to a product.

## Data Models

### `InventoryApp`

Defined in `app_utils/software_inventory.py`.

```python
@dataclass(frozen=True)
class InventoryApp:
    display_name: str
    executable_name: str
    path: str
    is_locked: bool = False
    sources: tuple[str, ...] = ()
```

Purpose:

- Represents one merged dashboard row.
- Carries both UI fields and lock state.
- Uses normalized path when available as the primary dedupe identity.

### `LockedAppRecord`

Defined in `app_utils/locked_apps_repository.py`.

```python
@dataclass(frozen=True)
class LockedAppRecord:
    id: int | None
    app_name: str
    app_path: str = ""
```

Purpose:

- Represents one persisted lock target.
- Preserves compatibility with the current `locked_apps` table.
- Exposes a stable identity for monitor suppression and prompt de-duplication.

## Database Schema

### Tables

#### `users`

```sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
)
```

#### `locked_apps`

```sql
CREATE TABLE IF NOT EXISTS locked_apps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_name TEXT NOT NULL,
    app_path TEXT NOT NULL DEFAULT ''
)
```

#### `security_logs`

```sql
CREATE TABLE IF NOT EXISTS security_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    details TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
```

#### `settings`

```sql
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
)
```

### Indexes and Uniqueness Rules

```sql
CREATE UNIQUE INDEX IF NOT EXISTS idx_locked_apps_unique_path
ON locked_apps(LOWER(app_path))
WHERE TRIM(app_path) <> '';

CREATE UNIQUE INDEX IF NOT EXISTS idx_locked_apps_unique_name_without_path
ON locked_apps(LOWER(app_name))
WHERE TRIM(app_path) = '';
```

Supporting indexes:

```sql
CREATE INDEX IF NOT EXISTS idx_locked_apps_name
ON locked_apps(LOWER(app_name));

CREATE INDEX IF NOT EXISTS idx_locked_apps_path
ON locked_apps(LOWER(app_path));
```

### Migration Behavior

On startup, `init_db()` now:

- Enables WAL mode and normal synchronous mode.
- Trims legacy `locked_apps` strings.
- Removes duplicate path-based rows.
- Removes duplicate name-only rows.
- Creates indexes after cleanup so legacy data does not fail migrations.

## API and Contracts

### Inventory Contracts

#### `build_software_inventory(locked_apps) -> list[InventoryApp]`

Responsibilities:

- Discover software from registry and Start Menu.
- Deduplicate by normalized path, then by executable name for pathless entries.
- Merge persisted locked state into inventory rows.
- Sort locked first and unlocked second.

#### Normalization Rules

- Normalize paths with `expandvars`, `expanduser`, `normpath`, and absolute conversion.
- Accept only existing `.exe` files as resolved executable paths.
- Ignore matches containing tokens such as `uninstall`, `setup`, `installer`, `updater`, or `repair`.
- If no valid path exists, keep the record and fall back to executable name or display name.

### Repository Contracts

#### `list_locked_apps() -> list[LockedAppRecord]`

- Returns all persisted lock targets in normalized form.

#### `lock_apps(apps) -> int`

- Inserts new lock records.
- Upgrades name-only records to path-backed records when a path later becomes available.
- Avoids duplicates through repository logic plus database indexes.

#### `unlock_apps(apps) -> int`

- Removes locks by database `id` when available.
- Falls back to normalized path or name-only delete logic when called from inventory rows.

### Monitor/Controller Contracts

#### `ProcessMonitor.scan_processes(callback)`

- Refreshes lock targets from the database.
- Matches running processes by normalized executable path first.
- Falls back to executable name when path is unavailable.
- Kills unauthorized matches and forwards the matching `LockedAppRecord`.

#### `Controller.on_prompt_result(locked_app, success)`

- Releases prompt de-duplication state.
- Relaunches only after successful master-password verification.
- Re-allows the approved process by PID after launch.

## UI Flow

### Startup Flow

1. `main.py` initializes the database and controller.
2. `Dashboard` opens.
3. If no master password exists, the setup dialog blocks until one is created.
4. The dashboard starts a background inventory refresh.
5. The Treeview renders the merged inventory.

### Dashboard Flow

1. User searches or scrolls the merged inventory.
2. User selects one or more rows.
3. User clicks `Lock Selected` or `Unlock Selected`.
4. A reusable password dialog verifies the master password.
5. Repository writes the state change.
6. Dashboard refreshes inventory and re-renders the Treeview.

### Intercept Flow

1. `ProcessMonitor` detects a locked executable.
2. The process is terminated.
3. `Controller` queues a prompt for the specific locked target.
4. `PasswordPrompt` verifies the password.
5. If approved, the controller suppresses that app briefly, relaunches it, and marks the spawned PID as allowed.

## State Management

### Dashboard State

`dashboard.py` maintains:

- `inventory_rows`: full merged inventory
- `displayed_rows`: search-filtered rows
- `tree_index`: Treeview item-to-row lookup
- `_refresh_token`: last refresh request identity
- `_refresh_in_progress`: refresh guard
- `refresh_results`: worker-to-UI queue

### Concurrency Model

- Inventory discovery runs in a background thread.
- Tkinter updates happen only on the main thread.
- Database writes are serialized through `write_connection()`.
- Monitor prompt duplication is prevented with `prompting_apps`.

## Critical Code Snippets

### 1. Serialized Database Writes

```python
@contextmanager
def write_connection():
    with _WRITE_LOCK:
        conn = get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
```

Why it matters:

- Prevents overlapping write races from the dashboard, auth logging, and future background tasks.

### 2. Inventory Merge and Sort

```python
return sorted(
    merged,
    key=lambda app: (
        0 if app.is_locked else 1,
        app.display_name.casefold(),
        app.executable_name.casefold(),
        normalize_path(app.path).casefold(),
    ),
)
```

Why it matters:

- Guarantees the required UX ordering without duplicating sort logic in the UI.

### 3. Path-First Enforcement

```python
def _match_locked_app(self, process_name: str, process_path: str) -> LockedAppRecord | None:
    if process_path:
        by_path_match = self.locked_by_path.get(process_path.casefold())
        if by_path_match is not None:
            return by_path_match

    if process_name:
        name_matches = self.locked_by_name.get(process_name.casefold(), [])
        if name_matches:
            return name_matches[0]

    return None
```

Why it matters:

- Reduces false positives when multiple applications share generic executable names.

### 4. Responsive Tkinter Refresh

```python
worker = threading.Thread(
    target=self._refresh_inventory_worker,
    args=(refresh_token,),
    daemon=True,
)
worker.start()
```

and

```python
def _poll_refresh_results(self):
    try:
        while True:
            refresh_token, inventory, error = self.refresh_results.get_nowait()
            self._apply_inventory_results(refresh_token, inventory, error)
    except queue.Empty:
        pass
```

Why it matters:

- Keeps the dashboard responsive while registry and Start Menu discovery run.

## Acceptance Criteria

The upgrade is complete when all of the following are true:

- On launch, the dashboard shows a merged software inventory without requiring manual file picking.
- Inventory includes data from registry, Start Menu shortcuts, and locked DB rows.
- Locked rows appear before unlocked rows.
- Rows are alphabetized inside each lock-state group.
- The Treeview displays `Status`, `Display Name`, `Executable`, and `Path`.
- Search filters rows by status, display name, executable name, path, or source text.
- `Refresh` rebuilds inventory without freezing the UI.
- `Lock Selected` writes new lock records only after password verification.
- `Unlock Selected` removes lock records only after password verification.
- Duplicate locks are prevented by repository logic and database indexes.
- The monitor still intercepts locked applications.
- The controller still relaunches approved applications after authentication.

## Testing Plan

### Immediate Verification

- `python -m compileall app_utils config monitoring security ui`
- Smoke test `build_software_inventory()` with `SECUREAPP_LOCKER_DATA_DIR` pointing to a writable test directory.
- Smoke test `lock_apps()` and `unlock_apps()` with a known executable such as `notepad.exe`.

### Manual Functional Tests

1. First-run setup
   - Delete the runtime database.
   - Launch the app.
   - Confirm the password setup dialog blocks until a valid password is saved.

2. Inventory discovery
   - Launch the dashboard.
   - Confirm installed software appears automatically.
   - Confirm rows with valid paths show real executable paths.

3. Search and sorting
   - Search by product name, executable name, and partial path.
   - Confirm locked entries stay grouped above unlocked entries.

4. Lock workflow
   - Select one or more unlocked apps.
   - Lock them.
   - Confirm the dashboard refreshes and rows move into the locked section.

5. Unlock workflow
   - Select locked rows.
   - Unlock them.
   - Confirm the rows move back into the unlocked section.

6. Enforcement workflow
   - Lock a test executable.
   - Start it directly outside the dashboard.
   - Confirm the process is terminated and the unlock prompt appears.
   - Approve launch and confirm the application opens successfully.

### Recommended Automated Tests

- Unit tests for path normalization and ignored-token filtering.
- Unit tests for repository dedupe and migration behavior.
- Integration test using a temporary runtime data directory.
- UI smoke test for `Dashboard.refresh_inventory()` in a mocked discovery environment.

## CI/CD Strategy

### CI Stages

1. `lint`
   - `python -m compileall`
   - Optional: `ruff check .`

2. `test`
   - Run unit and integration tests with `SECUREAPP_LOCKER_DATA_DIR` set to a temporary workspace directory.

3. `package`
   - Build the Windows executable with PyInstaller:
     - `pyinstaller SecureAppLocker.spec`

4. `smoke`
   - Launch the packaged executable in a clean Windows runner.
   - Verify DB bootstrap and process startup.

### Release Gates

- No compile failures
- No failing unit or integration tests
- Packaged executable builds successfully
- Manual security smoke test passed on Windows

### Example GitHub Actions Outline

```yaml
name: secureapp-locker-ci

on:
  push:
  pull_request:

jobs:
  windows-build:
    runs-on: windows-latest
    env:
      SECUREAPP_LOCKER_DATA_DIR: ${{ github.workspace }}\\.runtime
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r requirements.txt
      - run: python -m compileall app_utils config monitoring security ui
      - run: python -m unittest discover -s tests
      - run: pyinstaller SecureAppLocker.spec
```

## Deployment Guide

### Local Development

```powershell
pip install -r requirements.txt
python main.py
```

### Writable Runtime Directory

By default the app stores runtime data in:

- `%LOCALAPPDATA%\SecureAppLocker\secureapp.db`
- `%LOCALAPPDATA%\SecureAppLocker\logs\secureapp.log`

For development, CI, or sandboxed environments, set:

```powershell
$env:SECUREAPP_LOCKER_DATA_DIR="D:\SecureApp Locker\.runtime"
```

### Packaging

```powershell
pyinstaller SecureAppLocker.spec
```

### Production Rollout Checklist

1. Build signed Windows artifact.
2. Verify runtime directory permissions for target users.
3. Run first-launch password setup.
4. Validate inventory population on both admin and standard-user accounts.
5. Validate interception and relaunch on at least one locked desktop app.

## Security Notes

- Lock and unlock actions remain password-gated.
- Password hashes remain bcrypt-based.
- Security events still log to `security_logs`.
- Registry reads are wrapped in safe parsing logic.
- Path resolution only trusts existing `.exe` files.
- The app now prefers path identity over name identity for higher precision.

## Scalability and Future Improvements

### Near-Term Improvements

- Persist a software inventory cache table for faster subsequent refreshes.
- Add publisher, version, install source, and last-seen timestamps to inventory rows.
- Add dashboard filters for `Locked`, `Unlocked`, `Missing Path`, and `Source`.
- Add export to CSV for audit and support workflows.

### Mid-Term Improvements

- Move process monitoring into a Windows service for stronger persistence.
- Introduce signed policy bundles and import/export of lock policy.
- Add role-based administration and password rotation flows.

### Long-Term Improvements

- Replace polling with WMI or ETW-backed process events.
- Support per-user and per-machine policy scopes.
- Add telemetry dashboards for intercept frequency and bypass attempts.

## Change Summary

Implemented files:

- `app_utils/software_inventory.py`
- `app_utils/locked_apps_repository.py`
- `config/config_manager.py`
- `monitoring/process_monitor.py`
- `controller.py`
- `ui/dashboard.py`
- `ui/password_prompt.py`
- `main.py`

Result:

- SecureApp Locker now behaves as an installed-software inventory and lock management platform while preserving its existing intercept-and-approve security model.
