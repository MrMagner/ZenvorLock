import ctypes

user32 = ctypes.windll.user32
GWL_EXSTYLE = -20
WS_EX_LAYERED = 0x00080000

def fix_alpha(hwnd, _lparam):
    try:
        exstyle = user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
        if exstyle & WS_EX_LAYERED:
            title_len = user32.GetWindowTextLengthW(hwnd)
            title_buf = ctypes.create_unicode_buffer(title_len + 1)
            user32.GetWindowTextW(hwnd, title_buf, title_len + 1)
            print(f"Removing layered style from HWND {hwnd}: {title_buf.value}", flush=True)
            user32.SetWindowLongW(hwnd, GWL_EXSTYLE, exstyle & ~WS_EX_LAYERED)
            user32.ShowWindow(hwnd, 5)
    except:
        pass
    return True

enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
print("Scanning and fixing all windows...", flush=True)
user32.EnumWindows(enum_proc(fix_alpha), 0)
