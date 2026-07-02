$ErrorActionPreference = 'Stop'
$package_name = '5319275A.WhatsAppDesktop_2.2620.102.0_x64__cv1g1gvanyjgm'
$executable_name = 'WhatsApp.exe'
$pkg = Get-AppxPackage | Where-Object PackageFullName -eq $package_name | Select-Object -First 1
if (-not $pkg) { throw "Package not found: $package_name" }
$manifest = [xml](Get-AppxPackageManifest -Package $pkg.PackageFullName)
$apps = @($manifest.Package.Applications.Application)
$app = $apps | Where-Object { $_.Executable -and ([System.IO.Path]::GetFileName($_.Executable) -ieq $executable_name) } | Select-Object -First 1
if (-not $app) { $app = $apps | Select-Object -First 1 }
if (-not $app -or -not $app.Id) { throw 'Application id not found.' }
$amuid = $pkg.PackageFamilyName + '!' + $app.Id
Write-Output $amuid
