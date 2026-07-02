from app_utils.locked_apps_repository import add_locked_app, get_locked_targets, remove_locked_app
from config.config_manager import write_connection, get_connection
import os
import time
import subprocess
import threading
from controller import Controller

print("Setting up...")
conn = get_connection()
cursor = conn.cursor()
cursor.execute("DELETE FROM locked_apps")
conn.commit()

# Find Calculator path
calc_path = r"C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_11.2401.0.0_x64__8wekyb3d8bbwe\CalculatorApp.exe"
if not os.path.exists(calc_path):
    print("Finding calc path...")
    import glob
    paths = glob.glob(r"C:\Program Files\WindowsApps\Microsoft.WindowsCalculator*\CalculatorApp.exe")
    if paths:
        calc_path = paths[0]
        print(f"Found calc at {calc_path}")

add_locked_app("Calculator", calc_path, "path")

print("Starting controller...")
c = Controller(None)
c.start()

def launch_calc():
    time.sleep(2)
    print("Launching Calculator...")
    subprocess.Popen(["calc.exe"])
    time.sleep(5)
    print("Is prompt showing?", c.prompt_in_progress)
    if c.prompt_in_progress:
        print("Unlocking Calculator!")
        apps = get_locked_targets()
        c.ui_queue.put(('success', apps[0]))
    
t = threading.Thread(target=launch_calc)
t.start()

try:
    while True:
        time.sleep(1)
        if not t.is_alive():
            break
except KeyboardInterrupt:
    pass

c.stop()
