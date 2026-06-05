Write-Host "Applying CIS Benchmark fixes..." -ForegroundColor Yellow

# Ensure running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You must run this script as Administrator!"
    exit
}

Start-Transcript -Path "C:\CIS-Benchmark-$(Get-Date -Format yyyyMMdd_HHmmss).log" -Append

# Function to set registry values
function Set-Registry {
    param (
        [string]$Path,
        [string]$Name,
        [Object]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
    )
    try {
        if (-not (Test-Path $Path)) { 
            New-Item -Path $Path -Force | Out-Null
        }

        $currentValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $currentValue -or "$($currentValue.$Name)" -ne "$Value") {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
            Write-Output "[FIXED] ${Path}\${Name} set to $Value"
        } else {
            Write-Output "[SKIPPED] ${Path}\${Name} is already set to $Value"
        }
    } catch {
        Write-Output "[ERROR] Could not set ${Path}\${Name}: $_"
    }
}

### --- CIS Fixes Start ---

# 9.1.1, 9.2.1, 9.3.1 - Windows Firewall state ON
#Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True

# 18.9.58.3.9.1 - Always prompt for password upon connection
Set-Registry -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "AlwaysPromptForPassword" -Value 1

# 18.9.80.1.1 - SmartScreen settings
$regPath = "HKLM:\Software\Policies\Microsoft\Windows\System"
Set-Registry -Path $regPath -Name "EnableSmartScreen" -Value 1
Set-Registry -Path $regPath -Name "ShellSmartScreenLevel" -Value "WarnAndPreventBypass" -Type String

# 18.9.100.1 - Turn on PowerShell Script Block Logging
Set-Registry -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# 19.1.3.1 - Enable screen saver
$regCU = "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
Set-Registry -Path $regCU -Name "ScreenSaveActive" -Value 1

# 19.1.3.2 - Password protect screen saver
Set-Registry -Path $regCU -Name "ScreenSaverIsSecure" -Value 1

# 19.1.3.3 - Screen saver timeout <= 900
Set-Registry -Path $regCU -Name "ScreenSaveTimeOut" -Value 900 -Type String

# 19.5.1.1 - Turn off toast notifications on lock screen
Set-Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Value 1

# 19.6.5.1.1 / 19.6.6.1.1 - Turn off Help Experience Improvement Program
Set-Registry -Path "HKLM:\Software\Policies\Microsoft\Assistance\Client\1.0" -Name "NoImplicitFeedback" -Value 1

# 19.7.4.1 - Do not preserve zone info (should be Disabled)
Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 1

# 19.7.4.2 - Notify AV programs when opening attachments
Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -Value 3

# 19.7.7.x / 19.7.8.x - Spotlight settings
$cloudPath = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
Set-Registry -Path $cloudPath -Name "DisableThirdPartySuggestions" -Value 1
Set-Registry -Path $cloudPath -Name "DisableWindowsSpotlightFeatures" -Value 1
Set-Registry -Path $cloudPath -Name "DisableSpotlightCollection" -Value 1

$persPath = "HKCU:\Software\Policies\Microsoft\Windows\Personalization"
Set-Registry -Path $persPath -Name "NoLockScreen" -Value 1

$datacollectPath = "HKCU:\Software\Policies\Microsoft\Windows\DataCollection"
Set-Registry -Path $datacollectPath -Name "AllowTailoredExperiences" -Value 0

# 19.7.26.1 / 19.7.28.1 - Prevent file sharing within profile
Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInplaceSharing" -Value 1

# 19.7.40.1 / 19.7.43.1 - Always install with elevated privileges (Disable this setting)
Set-Registry -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0
Set-Registry -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0

# 19.7.44.2.1 / 19.7.47.2.1 - Prevent Codec Download
Set-Registry -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Media Player" -Name "PreventCodecDownload" -Value 1

# Screen saver executable (CIS 19.1.3.2)
Set-Registry -Path $regCU -Name "SCRNSAVE.EXE" -Value "scrnsave.scr" -Type String

Write-Host "`nAll applicable CIS Benchmark settings have been applied." -ForegroundColor Green
Stop-Transcript
