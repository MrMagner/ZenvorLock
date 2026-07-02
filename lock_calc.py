import sqlite3
import os

# Ensure calculator is locked
db_path = r"C:\Users\magne\AppData\Local\ZenvorLock\app.db"
os.makedirs(os.path.dirname(db_path), exist_ok=True)
conn = sqlite3.connect(db_path)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS locked_apps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_name TEXT NOT NULL,
                    app_path TEXT NOT NULL,
                    match_mode TEXT DEFAULT 'path',
                    file_sha256 TEXT DEFAULT '',
                    integrity_issue TEXT DEFAULT ''
                )''')
cursor.execute("DELETE FROM locked_apps")

calc_path = ""
import glob
paths = glob.glob(r"C:\Program Files\WindowsApps\Microsoft.WindowsCalculator*\CalculatorApp.exe")
if paths:
    calc_path = paths[0]
    cursor.execute("INSERT INTO locked_apps (app_name, app_path, match_mode) VALUES (?, ?, ?)", ("Calculator", calc_path, "path"))
    conn.commit()
    print(f"Locked Calculator at {calc_path}")
else:
    print("Could not find Calculator!")
conn.close()
