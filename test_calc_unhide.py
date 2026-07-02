import ctypes
import psutil
import time

user32 = ctypes.windll.user32
GWL_EXSTYLE = -20
WS_EX_LAYERED = 0x00080000
LWA_ALPHA = 2

calc_pid = None
for p in psutil.process_iter(['name', 'pid']):
    if 'calculator' in (p.info['name'] or '').lower():
        calc_pid = p.pid
        break

if not calc_pid:
    print("Calc not running!")
    exit()

hidden_hwnds = set()

def hide_window(hwnd, _lparam):
    pid = ctypes.c_ulong()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if pid.value == calc_pid:
        parent = user32.GetAncestor(hwnd, 2)
        if parent and parent != hwnd:
            exstyle = user32.GetWindowLongW(parent, GWL_EXSTYLE)
            user32.SetWindowLongW(parent, GWL_EXSTYLE, exstyle | WS_EX_LAYERED)
            user32.SetLayeredWindowAttributes(parent, 0, 0, LWA_ALPHA)
            hidden_hwnds.add(parent)
            print(f"HIDDEN parent {parent}")
    return True

enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

# 1. Hide it
user32.EnumWindows(enum_proc(hide_window), 0)
user32.EnumChildWindows(user32.GetDesktopWindow(), enum_proc(hide_window), 0)

print(f"Hidden HWNDs: {hidden_hwnds}")
time.sleep(2)

# 2. Kill it!
print("Killing calc...")
psutil.Process(calc_pid).kill()
time.sleep(2)

# 3. Relaunch it!
print("Relaunching calc...")
import subprocess
subprocess.Popen("calc.exe")
time.sleep(3) # Wait for it to spawn transparently

# 4. Unhide it!
print("Unhiding HWNDs directly...")
for hwnd in hidden_hwnds:
    exstyle = user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
    if exstyle & WS_EX_LAYERED:
        print(f"Removing LAYERED from {hwnd}")
        user32.SetWindowLongW(hwnd, GWL_EXSTYLE, exstyle & ~WS_EX_LAYERED)
    else:
        print(f"NOT LAYERED: {hwnd}")

print("Done! Check if calc is visible on your screen.")
