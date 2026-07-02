import os
from pathlib import PureWindowsPath

def _is_windows_store_app_path(path: str) -> bool:
    return any(part.casefold() == "windowsapps" for part in PureWindowsPath(path).parts)

def _windows_store_package_from_path(path: str) -> str:
    parts = PureWindowsPath(path).parts
    for index, part in enumerate(parts):
        if part.casefold() == "windowsapps" and index + 1 < len(parts):
            return parts[index + 1]
    return ""

def _resolve_amuid(path: str) -> str:
    package_full_name = _windows_store_package_from_path(path)
    if not package_full_name:
        return ""
        
    manifest_path = os.path.join(os.environ.get("ProgramW6432", "C:\\Program Files"), "WindowsApps", package_full_name, "AppxManifest.xml")
    if not os.path.exists(manifest_path):
        return ""
        
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        
        for elem in root.iter():
            if '}' in elem.tag:
                elem.tag = elem.tag.split('}', 1)[1]
                
        identity = root.find('Identity')
        if identity is None: return ""
        
        parts = package_full_name.split("_")
        if len(parts) >= 2:
            package_family_name = identity.get('Name') + "_" + parts[-1]
        else:
            return ""
            
        applications = root.find('Applications')
        if applications is None: return ""
        
        target_exe = os.path.basename(path).casefold()
        for app in applications.findall('Application'):
            exe = app.get('Executable', '')
            if os.path.basename(exe).casefold() == target_exe:
                return f"{package_family_name}!{app.get('Id')}"
                
        first_app = applications.find('Application')
        if first_app is not None:
            return f"{package_family_name}!{first_app.get('Id')}"
            
        return ""
    except Exception as e:
        return ""

print(_resolve_amuid(r"C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2620.102.0_x64__cv1g1gvanyjgm\WhatsApp.exe"))
