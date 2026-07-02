import ctypes
import psutil
import time

user32 = ctypes.windll.user32
enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

whatsapp_pids = set()
for p in psutil.process_iter(['name', 'pid']):
    if 'whatsapp' in (p.info['name'] or '').lower():
        whatsapp_pids.add(p.pid)

def show_window(hwnd, _lparam):
    pid = ctypes.c_ulong()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if pid.value in whatsapp_pids:
        parent = user32.GetAncestor(hwnd, 2)
        if parent:
            print(f"Showing parent {parent}")
            user32.ShowWindow(parent, 5) # SW_SHOW
            user32.ShowWindow(hwnd, 5)
    return True

print("Showing windows...")
user32.EnumWindows(enum_proc(show_window), 0)
user32.EnumChildWindows(user32.GetDesktopWindow(), enum_proc(show_window), 0)
