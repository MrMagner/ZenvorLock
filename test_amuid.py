import os
import glob
from controller import Controller

controller = Controller(None)

paths = glob.glob(r"C:\Program Files\WindowsApps\*WhatsApp*\WhatsApp.exe")
if not paths:
    paths = glob.glob(r"C:\Program Files\WindowsApps\*WhatsApp*\WhatsApp.Root.exe")
    
for path in paths:
    print(f"Path: {path}")
    amuid = controller._resolve_amuid(path)
    print(f"Resolved AMUID: {amuid}")
    if amuid:
        print(f"Test command: explorer.exe shell:AppsFolder\\{amuid}")
