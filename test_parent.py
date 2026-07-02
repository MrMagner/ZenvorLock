import ctypes

user32 = ctypes.windll.user32
hwnd = 590876
parent = user32.GetAncestor(hwnd, 2)
print(f"Parent of {hwnd} is {parent}")
pid = ctypes.c_ulong()
user32.GetWindowThreadProcessId(parent, ctypes.byref(pid))
print(f"Parent PID is {pid.value}")
