from controller import Controller
from app_utils.locked_apps_repository import LockedAppRecord

c = Controller(None)
app = LockedAppRecord(
    id=1,
    app_name="WhatsApp",
    app_path=r"c:\program files\windowsapps\5319275a.whatsappdesktop_2.2421.7.0_x64__cv1g1gvanyjgm\whatsapp.exe"
)
amuid = c._resolve_amuid(app.app_path)
print(f"AMUID: {amuid}")
