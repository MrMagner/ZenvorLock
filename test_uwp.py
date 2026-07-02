import psutil
import time
import subprocess

print("Looking for WhatsApp processes...")
pids = []
for p in psutil.process_iter(['name', 'pid']):
    if p.info['name'] and 'whatsapp' in p.info['name'].lower():
        pids.append(p)

print(f"Found {len(pids)} processes: {[p.name() for p in pids]}")

for p in pids:
    print(f"Terminating {p.pid} ({p.name()})")
    try:
        p.terminate()
        p.wait(timeout=3)
        print("Terminated.")
    except Exception as e:
        print(f"Error: {e}")

print("Done killing. Are there any left?")
for p in psutil.process_iter(['name', 'pid']):
    if p.info['name'] and 'whatsapp' in p.info['name'].lower():
        print(f"STILL ALIVE: {p.pid} ({p.name()})")
