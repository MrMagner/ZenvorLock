import psutil
import time

whatsapp_pid = None
for p in psutil.process_iter(['name', 'pid']):
    if 'whatsapp' in (p.info['name'] or '').lower():
        whatsapp_pid = p.pid
        break

if whatsapp_pid:
    print(f"Killing {whatsapp_pid}...")
    p = psutil.Process(whatsapp_pid)
    # Just kill it directly without touching windows
    p.kill()
    print("Killed!")
else:
    print("WhatsApp not running")
