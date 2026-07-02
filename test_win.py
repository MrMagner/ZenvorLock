import ctypes
import ctypes.wintypes
import psutil

user32 = ctypes.windll.user32
dwmapi = ctypes.windll.dwmapi

def check_whatsapp_windows():
    whatsapp_pids = []
    for p in psutil.process_iter(['name', 'pid']):
        if p.info['name'] and 'whatsapp' in p.info['name'].lower():
            whatsapp_pids.append(p.pid)
            
    if not whatsapp_pids:
        print("WhatsApp is not running.")
        return
        
    print(f"Found WhatsApp PIDs: {whatsapp_pids}")
    
    enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    visible_hwnds = []

    def check_window(hwnd, _lparam):
        pid = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        
        if pid.value in whatsapp_pids:
            visible = user32.IsWindowVisible(hwnd)
            
            cloaked = ctypes.c_int(0)
            is_cloaked = False
            if dwmapi.DwmGetWindowAttribute(hwnd, 14, ctypes.byref(cloaked), ctypes.sizeof(cloaked)) == 0:
                is_cloaked = cloaked.value != 0
                
            rect = ctypes.wintypes.RECT()
            width, height = 0, 0
            if user32.GetWindowRect(hwnd, ctypes.byref(rect)):
                width = rect.right - rect.left
                height = rect.bottom - rect.top
                
            print(f"HWND: {hwnd}, PID: {pid.value}, Visible: {visible}, Cloaked: {is_cloaked}, Size: {width}x{height}")
            if visible and not is_cloaked and width > 0 and height > 0:
                visible_hwnds.append(hwnd)
                
        return True

    user32.EnumWindows(enum_proc(check_window), 0)
    print(f"Real visible WhatsApp top-level windows: {visible_hwnds}")
    
    # Also check child windows of Desktop
    def check_child(hwnd, _lparam):
        pid = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value in whatsapp_pids:
            visible = user32.IsWindowVisible(hwnd)
            cloaked = ctypes.c_int(0)
            is_cloaked = False
            if dwmapi.DwmGetWindowAttribute(hwnd, 14, ctypes.byref(cloaked), ctypes.sizeof(cloaked)) == 0:
                is_cloaked = cloaked.value != 0
            rect = ctypes.wintypes.RECT()
            width, height = 0, 0
            if user32.GetWindowRect(hwnd, ctypes.byref(rect)):
                width = rect.right - rect.left
                height = rect.bottom - rect.top
            print(f"Child HWND: {hwnd}, PID: {pid.value}, Visible: {visible}, Cloaked: {is_cloaked}, Size: {width}x{height}")
        return True
        
    desktop = user32.GetDesktopWindow()
    user32.EnumChildWindows(desktop, enum_proc(check_child), 0)

check_whatsapp_windows()
