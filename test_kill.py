import psutil
import time

whatsapp_pids = []
for p in psutil.process_iter(['name']):
    if p.info['name'] and 'whatsapp' in p.info['name'].lower():
        whatsapp_pids.append(p)

print(f"Found {len(whatsapp_pids)} WhatsApp processes.")

for p in whatsapp_pids:
    print(f"Terminating PID {p.pid} ({p.name()})...")
    try:
        p.terminate()
        p.wait(timeout=2)
        print("Terminated successfully.")
    except psutil.AccessDenied:
        print("AccessDenied on terminate(). Trying kill()...")
        try:
            p.kill()
            p.wait(timeout=2)
            print("Killed successfully.")
        except Exception as e:
            print(f"Kill also failed: {e}")
    except psutil.TimeoutExpired:
        print("Timeout on terminate(). Trying kill()...")
        try:
            p.kill()
            p.wait(timeout=2)
            print("Killed successfully.")
        except Exception as e:
            print(f"Kill also failed: {e}")
    except Exception as e:
        print(f"Error: {e}")
