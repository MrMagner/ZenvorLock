from app_utils.locked_apps_repository import get_locked_targets
from monitoring.process_monitor import ProcessMonitor
import time
import subprocess
import threading

def on_password(app):
    print(f"Intercepted {app.app_name}!")
    
    def simulate_user():
        print("Simulating user entering password (waiting 3s)...")
        time.sleep(3)
        print("Authorizing app session!")
        monitor.authorize_app_session(app, startup_grace=15.0)
        
        # Launch it like controller does
        amuid = "Microsoft.WindowsNotepad_8wekyb3d8bbwe!App"
        print(f"Launching AMUID {amuid}...")
        subprocess.Popen(["explorer.exe", f"shell:AppsFolder\\{amuid}"])
        
    threading.Thread(target=simulate_user).start()

print("Starting monitor...")
monitor = ProcessMonitor()
monitor.on_app_intercepted.append(on_password)
monitor.start()

print("Launching Notepad...")
subprocess.Popen(["notepad.exe"])

try:
    time.sleep(15)
except KeyboardInterrupt:
    pass

monitor.stop()
print("Done.")
