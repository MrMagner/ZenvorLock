import os
import xml.etree.ElementTree as ET

path = r"C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2620.102.0_x64__cv1g1gvanyjgm\WhatsApp.exe"
parts = os.path.normpath(path).split(os.sep)
package_full_name = ""
for i, part in enumerate(parts):
    if part.casefold() == "windowsapps" and i + 1 < len(parts):
        package_full_name = parts[i + 1]
        break

print("PackageFullName:", package_full_name)

manifest_path = os.path.join("C:\\Program Files", "WindowsApps", package_full_name, "AppxManifest.xml")
print("Manifest Path:", manifest_path)

tree = ET.parse(manifest_path)
root = tree.getroot()
for elem in root.iter():
    if '}' in elem.tag:
        elem.tag = elem.tag.split('}', 1)[1]

identity = root.find('Identity')
publisher_hash = package_full_name.split("_")[-1]
package_family_name = identity.get('Name') + "_" + publisher_hash

applications = root.find('Applications')
target_exe = os.path.basename(path).casefold()

amuid = ""
for app in applications.findall('Application'):
    exe = app.get('Executable', '')
    if os.path.basename(exe).casefold() == target_exe:
        amuid = f"{package_family_name}!{app.get('Id')}"
        break

print("AMUID:", amuid)
