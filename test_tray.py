import psutil
import time
import subprocess
import ctypes

user32 = ctypes.windll.user32

print("Launching WhatsApp...")
subprocess.Popen(["explorer.exe", "shell:AppsFolder\\5319275A.WhatsAppDesktop_cv1g1gvanyjgm!App"], close_fds=True)
time.sleep(3)

whatsapp_pids = set()
for p in psutil.process_iter(['name', 'pid']):
    if 'whatsapp' in (p.info['name'] or '').lower():
        whatsapp_pids.add(p.pid)

enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
dwmapi = ctypes.windll.dwmapi

def check_window(hwnd, _lparam):
    pid = ctypes.c_ulong()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if pid.value in whatsapp_pids:
        visible = user32.IsWindowVisible(hwnd)
        rect = ctypes.wintypes.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        print(f"HWND: {hwnd}, Visible: {visible}, Rect: ({rect.left},{rect.top},{rect.right},{rect.bottom})")
    return True

print("Before closing:")
user32.EnumWindows(enum_proc(check_window), 0)

# Find the main ApplicationFrameHost window for WhatsApp and close it
def close_main(hwnd, _lparam):
    pid = ctypes.c_ulong()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if pid.value in whatsapp_pids:
        parent = user32.GetAncestor(hwnd, 2)
        if parent:
            print(f"Closing main frame {parent}")
            user32.PostMessageW(parent, 0x0010, 0, 0) # WM_CLOSE
            return False
    return True

user32.EnumWindows(enum_proc(close_main), 0)

time.sleep(3)
print("After closing (should be in tray):")
user32.EnumWindows(enum_proc(check_window), 0)
user32.EnumChildWindows(user32.GetDesktopWindow(), enum_proc(check_window), 0)

print("Killing...")
for p in psutil.process_iter(['name']):
    if 'whatsapp' in (p.info['name'] or '').lower():
        p.kill()
