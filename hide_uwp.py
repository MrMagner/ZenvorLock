import psutil
import time
import subprocess
import ctypes

user32 = ctypes.windll.user32

print("Launching WhatsApp...")
subprocess.Popen(["explorer.exe", "shell:AppsFolder\\5319275A.WhatsAppDesktop_cv1g1gvanyjgm!App"], close_fds=True)

time.sleep(1)

print("Hiding windows...")
whatsapp_pids = set()
for p in psutil.process_iter(['name', 'pid']):
    if 'whatsapp' in (p.info['name'] or '').lower():
        whatsapp_pids.add(p.pid)

enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

def hide_window(hwnd, _lparam):
    pid = ctypes.c_ulong()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    
    if pid.value in whatsapp_pids:
        # Hide the window
        print(f"Hiding window {hwnd} of PID {pid.value}")
        user32.ShowWindow(hwnd, 0) # SW_HIDE
        
        # If it's a child of ApplicationFrameHost, hide the parent too!
        parent = user32.GetAncestor(hwnd, 2) # GA_ROOT
        if parent and parent != hwnd:
            length = user32.GetWindowTextLengthW(parent)
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(parent, buf, length + 1)
            print(f"Hiding Root Parent {parent}: {buf.value}")
            user32.ShowWindow(parent, 0) # SW_HIDE
    return True

user32.EnumWindows(enum_proc(hide_window), 0)
user32.EnumChildWindows(user32.GetDesktopWindow(), enum_proc(hide_window), 0)

print("Windows hidden. Terminating processes...")
for p in psutil.process_iter(['name']):
    if 'whatsapp' in (p.info['name'] or '').lower():
        p.kill()

print("Done.")
