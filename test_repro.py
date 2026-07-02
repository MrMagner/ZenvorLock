import ctypes
import psutil

user32 = ctypes.windll.user32

whatsapp_pid = None
for p in psutil.process_iter(['name', 'pid']):
    if 'whatsapp' in (p.info['name'] or '').lower():
        whatsapp_pid = p.pid
        break

if not whatsapp_pid:
    print("WhatsApp not running")
    exit()

print(f"Target PID: {whatsapp_pid}")
def print_window(hwnd, _lparam):
    pid = ctypes.c_ulong()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if pid.value == whatsapp_pid:
        title_len = user32.GetWindowTextLengthW(hwnd)
        title_buf = ctypes.create_unicode_buffer(title_len + 1)
        user32.GetWindowTextW(hwnd, title_buf, title_len + 1)
        print(f"HWND {hwnd} owned by WhatsApp. Title: '{title_buf.value}'")
    return True

enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
user32.EnumWindows(enum_proc(print_window), 0)
user32.EnumChildWindows(user32.GetDesktopWindow(), enum_proc(print_window), 0)
