import psutil

for p in psutil.process_iter(['name', 'pid', 'create_time']):
    if 'whatsapp' in (p.info['name'] or '').lower():
        print(f"PID: {p.pid}, Name: {p.info['name']}, Create Time: {p.info['create_time']}")
