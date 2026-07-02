# SecureApp Locker

SecureApp Locker is a Windows desktop app that blocks configured executables until the user enters the master password.

## Project Layout

- `main.py`: Tkinter and tray entrypoint
- `controller.py`: monitor and unlock flow coordination
- `config/`: database initialization and access
- `monitoring/`: process scanning and enforcement
- `security/`: password setup, verification, and audit logging
- `ui/`: dashboard and unlock prompt windows
- `app_utils/`: shared runtime paths and logging helpers

## Runtime Data

The app now stores its writable runtime files outside the project tree:

- Database: `%LOCALAPPDATA%\SecureAppLocker\secureapp.db`
- Log file: `%LOCALAPPDATA%\SecureAppLocker\logs\secureapp.log`

Set `SECUREAPP_LOCKER_DATA_DIR` to override the runtime data directory.

On the first run after this change, the app copies legacy `secureapp.db` and `logs\secureapp.log` files into the new runtime location if they exist.

## Development

Install dependencies from `requirements.txt`, then run:

```powershell
python main.py
```

`build/`, `dist/`, virtual environments, logs, and local database files are generated artifacts and should not be treated as source files.
