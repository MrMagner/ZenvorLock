import ctypes
import ctypes.wintypes
import psutil
import time

user32 = ctypes.windll.user32

whatsapp_pids = set()
for p in psutil.process_iter(['name', 'pid']):
    if 'whatsapp' in (p.info['name'] or '').lower():
        whatsapp_pids.add(p.pid)

def close_window(hwnd, _lparam):
    pid = ctypes.c_ulong()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if pid.value in whatsapp_pids:
        parent = user32.GetAncestor(hwnd, 2)
        if parent:
            print(f"Closing parent {parent}")
            user32.PostMessageW(parent, 0x0010, 0, 0) # WM_CLOSE
            return False
    return True

print("Closing WhatsApp...")
enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
user32.EnumWindows(enum_proc(close_window), 0)

time.sleep(3)

def check_window(hwnd, _lparam):
    pid = ctypes.c_ulong()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if pid.value in whatsapp_pids:
        visible = user32.IsWindowVisible(hwnd)
        rect = ctypes.wintypes.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        width = rect.right - rect.left
        height = rect.bottom - rect.top
        
        if visible:
            print(f"VISIBLE HWND: {hwnd}, PID: {pid.value}, Size: {width}x{height}, Pos: ({rect.left},{rect.top})")
    return True

print("Checking windows after close...")
user32.EnumWindows(enum_proc(check_window), 0)
user32.EnumChildWindows(user32.GetDesktopWindow(), enum_proc(check_window), 0)
