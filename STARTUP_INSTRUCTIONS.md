# How to Add SecureApp Locker to Windows Startup

To launch SecureApp Locker automatically when Windows starts:

1. Create a shortcut.
   Open `dist\SecureAppLocker`, right-click `SecureAppLocker.exe`, and create a shortcut.

2. Open the Startup folder.
   Press `Win + R`, run `shell:startup`, and wait for the Startup folder to open.

3. Move the shortcut.
   Copy the shortcut from Step 1 into the Startup folder.

4. Verify the runtime data location.
   SecureApp Locker now stores its writable files in `%LOCALAPPDATA%\SecureAppLocker`:
   - `secureapp.db`
   - `logs\secureapp.log`

5. Restart and confirm.
   After the next sign-in, the app should launch in the background and remain available from the system tray.
