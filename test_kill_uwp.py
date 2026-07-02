import psutil
import time
import subprocess
import ctypes

user32 = ctypes.windll.user32

print("Launching WhatsApp...")
subprocess.Popen(["explorer.exe", "shell:AppsFolder\\5319275A.WhatsAppDesktop_cv1g1gvanyjgm!App"], close_fds=True)

time.sleep(5)

print("Killing WhatsApp.Root.exe...")
for p in psutil.process_iter(['name']):
    if 'whatsapp' in (p.info['name'] or '').lower():
        p.kill()

print("Killed. Waiting 5 seconds to see if window stays open...")
time.sleep(5)

enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
found = False
def check_window(hwnd, _lparam):
    global found
    if user32.IsWindowVisible(hwnd):
        length = user32.GetWindowTextLengthW(hwnd)
        if length > 0:
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            if 'WhatsApp' in buf.value:
                print(f"Window still open: {buf.value}")
                found = True
    return True

user32.EnumWindows(enum_proc(check_window), 0)
if not found:
    print("No WhatsApp window found.")
