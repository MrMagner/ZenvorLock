import psutil
import ctypes
import ctypes.wintypes

user32 = ctypes.windll.user32
dwmapi = ctypes.windll.dwmapi

whatsapp_pids = set()
for p in psutil.process_iter(['name', 'pid']):
    if 'whatsapp' in (p.info['name'] or '').lower():
        whatsapp_pids.add(p.pid)

if not whatsapp_pids:
    print("WhatsApp is not running.")
    exit()

print(f"WhatsApp PIDs: {whatsapp_pids}")

def check_window(hwnd, _lparam):
    pid = ctypes.c_ulong()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if pid.value in whatsapp_pids:
        visible = user32.IsWindowVisible(hwnd)
        
        cloaked = ctypes.c_int(0)
        dwmapi.DwmGetWindowAttribute(hwnd, 14, ctypes.byref(cloaked), ctypes.sizeof(cloaked))
        
        rect = ctypes.wintypes.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        width = rect.right - rect.left
        height = rect.bottom - rect.top
        
        title_len = user32.GetWindowTextLengthW(hwnd)
        title_buf = ctypes.create_unicode_buffer(title_len + 1)
        user32.GetWindowTextW(hwnd, title_buf, title_len + 1)
        title = title_buf.value
        
        if visible:
            print(f"VISIBLE HWND: {hwnd}, PID: {pid.value}, Cloaked: {cloaked.value}, Size: {width}x{height}, Pos: ({rect.left},{rect.top}), Title: '{title}'")
        else:
            # only print hidden if they are large
            if width > 10 and height > 10:
                print(f"HIDDEN HWND: {hwnd}, PID: {pid.value}, Cloaked: {cloaked.value}, Size: {width}x{height}, Pos: ({rect.left},{rect.top}), Title: '{title}'")
                
    return True

enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
print("--- Desktop Windows ---")
user32.EnumWindows(enum_proc(check_window), 0)
print("--- Child Windows ---")
user32.EnumChildWindows(user32.GetDesktopWindow(), enum_proc(check_window), 0)
