import ctypes
import psutil
import time

user32 = ctypes.windll.user32
GWL_EXSTYLE = -20
WS_EX_LAYERED = 0x00080000
LWA_ALPHA = 0x00000002

whatsapp_pids = set()
for p in psutil.process_iter(['name', 'pid']):
    if 'whatsapp' in (p.info['name'] or '').lower():
        whatsapp_pids.add(p.pid)

def alpha_window(hwnd, _lparam):
    pid = ctypes.c_ulong()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if pid.value in whatsapp_pids:
        parent = user32.GetAncestor(hwnd, 2)
        if parent:
            print(f"Making transparent parent {parent}")
            exstyle = user32.GetWindowLongW(parent, GWL_EXSTYLE)
            user32.SetWindowLongW(parent, GWL_EXSTYLE, exstyle | WS_EX_LAYERED)
            user32.SetLayeredWindowAttributes(parent, 0, 0, LWA_ALPHA)
            return False
    return True

print("Making WhatsApp transparent...")
enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
user32.EnumWindows(enum_proc(alpha_window), 0)
