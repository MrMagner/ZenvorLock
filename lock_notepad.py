import sqlite3
import os

db_path = r"C:\Users\magne\AppData\Local\ZenvorLock\app.db"
conn = sqlite3.connect(db_path)
cursor = conn.cursor()
cursor.execute("DELETE FROM locked_apps")

notepad_path = r"C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2604.5.0_x64__8wekyb3d8bbwe\Notepad.exe"
cursor.execute("INSERT INTO locked_apps (app_name, app_path, match_mode) VALUES (?, ?, ?)", ("Notepad", notepad_path, "path"))
conn.commit()
print("Locked Notepad!")
conn.close()
