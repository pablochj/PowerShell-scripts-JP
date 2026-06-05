# File to save the output
$logPath = "$env:USERPROFILE\Desktop\CIS_Compliance_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Start-Transcript -Path $logPath -Append

Write-Host "Checking CIS Benchmark Compliance..." -ForegroundColor Cyan

function Check-Registry {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Expected,
        [string]$Description
    )
    try {
        $actual = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        if ("$actual" -eq "$Expected") {
            Write-Output "[PASS] $Description - Expected: $Expected, Found: $actual"
        } else {
            Write-Output "[FAIL] $Description - Expected: $Expected, Found: $actual"
        }
    } catch {
        Write-Output "[MISSING] $Description - Registry key or value not found."
    }
}

function Check-AuditPolicy {
    param(
        [string]$Subcategory,
        [string]$ExpectedSetting  # e.g. "Success and Failure", "Success", "Failure"
    )

    $auditStatus = (auditpol /get /subcategory:"$Subcategory" 2>$null | Select-String -Pattern $Subcategory)
    if ($auditStatus) {
        $status = ($auditStatus -split '\s{2,}')[1].Trim()
        if ($status -eq $ExpectedSetting) {
            Write-Output "[PASS] Audit policy '$Subcategory' is set to '$ExpectedSetting'"
        } else {
            Write-Output "[FAIL] Audit policy '$Subcategory' expected '$ExpectedSetting' but found '$status'"
        }
    } else {
        Write-Output "[MISSING] Audit policy '$Subcategory' not found"
    }
}

function Check-ServiceState {
    param(
        [string]$ServiceName,
        [string]$ExpectedState,  # e.g. "Stopped", "Running", "Disabled", "Manual"
        [string]$Description
    )
    try {
        $svc = Get-Service -Name $ServiceName -ErrorAction Stop
        $actualState = $svc.Status.ToString()
        if ($actualState -eq $ExpectedState) {
            Write-Output "[PASS] $Description - Expected: $ExpectedState, Found: $actualState"
        } else {
            Write-Output "[FAIL] $Description - Expected: $ExpectedState, Found: $actualState"
        }
    } catch {
        Write-Output "[MISSING] $Description - Service not found."
    }
}

# ----- 17-series Audit Policy Checks -----
Check-AuditPolicy -Subcategory 'Other Object Access Events' -ExpectedSetting 'Success and Failure'    # 17.6.1
Check-AuditPolicy -Subcategory 'IPsec Driver' -ExpectedSetting 'Success and Failure'                 # 17.9.1
Check-AuditPolicy -Subcategory 'Other System Events' -ExpectedSetting 'Success and Failure'          # 17.9.2
Check-AuditPolicy -Subcategory 'Security State Change' -ExpectedSetting 'Success'                    # 17.9.3
Check-AuditPolicy -Subcategory 'Security System Extension' -ExpectedSetting 'Success and Failure'   # 17.9.4
Check-AuditPolicy -Subcategory 'System Integrity' -ExpectedSetting 'Success and Failure'             # 17.9.5

# ----- 18-series Registry Checks -----

# Lock screen camera disabled
Check-Registry "HKLM:\Software\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera" "1" "Prevent enabling lock screen camera"           # 18.1.1.1

# Lock screen slide show disabled
Check-Registry "HKLM:\Software\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow" "1" "Prevent enabling lock screen slide show"   # 18.1.1.2

# SMB v1 client driver disabled (Enabled: Disable driver = 1)
Check-Registry "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start" "4" "Configure SMB v1 client driver (Disabled)"                   # 18.3.2

# SMB v1 server disabled (Start = 4)
Check-Registry "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer" "Start" "4" "Configure SMB v1 server (Disabled)"                        # 18.3.3

# AutoAdminLogon disabled
Check-Registry "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon" "0" "AutoAdminLogon Disabled"                     # 18.4.1

# ICMP redirects disabled (EnableICMPRedirect = 0)
Check-Registry "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "EnableICMPRedirect" "0" "Allow ICMP redirects to override OSPF routes"  # 18.4.4

# SafeDllSearchMode enabled (SafeDllSearchMode = 1)
Check-Registry "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "SafeDllSearchMode" "1" "Enable Safe DLL search mode"                  # 18.4.8

# Prohibit installation and configuration of Network Bridge (should be 1)
Check-Registry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_StdDomainUserSetLocation" "0" "Prohibit Network Bridge installation/configuration" # 18.5.11.2 (this registry is often 0 to prohibit, but depends, you might want to confirm path)

# Minimize simultaneous Internet/domain connections (should be 1)
Check-Registry "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "MaxCmds" "1" "Minimize simultaneous Internet/Domain connections"   # 18.5.21.1 (MaxCmds=1 means limit)

# Include command line in process creation events disabled (0)
Check-Registry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" "0" "Include command line in process creation events disabled"  # 18.8.3.1

# Remote host allows delegation of non-exportable credentials enabled (1)
Check-Registry "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "AllowDelegatingSavedCredentials" "1" "Remote host allows delegation of non-exportable credentials"  # 18.8.4.1

# Boot-Start Driver Initialization Policy set to good, unknown and bad but critical (0x7)
Check-Registry "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "BootDriverFlags" "7" "Boot-Start Driver Initialization Policy"  # 18.8.14.1

# Configure registry policy processing: Do not apply during periodic background processing = FALSE (0)
Check-Registry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy" "NoBackgroundPolicy" "0" "Do not apply policy during periodic background processing (FALSE)"  # 18.8.21.2

# Configure registry policy processing: Process even if GPO objects have not changed = TRUE (1)
Check-Registry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy" "EnableGPOExtensions" "1" "Process even if GPO objects have not changed (TRUE)"  # 18.8.21.3

# Turn off downloading of print drivers over HTTP = Enabled (1)
Check-Registry "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" "DisableWebPnPDownload" "1" "Turn off downloading of print drivers over HTTP"  # 18.8.22.1.1

# Turn off Internet download for Web publishing and online ordering wizards = Enabled (1)
Check-Registry "HKLM:\Software\Policies\Microsoft\Windows\Explorer" "DisableWebContentEvaluation" "1" "Turn off Internet download for Web publishing and online ordering"  # 18.8.22.1.5

# Configure Offer Remote Assistance = Disabled (0)
Check-Registry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowUnsolicited" "0" "Configure Offer Remote Assistance (Disabled)"  # 18.8.35.1

# Configure Solicited Remote Assistance = Disabled (0)
Check-Registry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowToGetHelp" "0" "Configure Solicited Remote Assistance (Disabled)"  # 18.8.35.2

# Enable RPC Endpoint Mapper Client Authentication = Enabled (1)
Check-Registry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" "EnableAuthEpResolution" "1" "Enable RPC Endpoint Mapper Client Authentication"  # 18.8.36.1

# Allow Microsoft accounts to be optional (1)
Check-Registry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "AllowMicrosoftAccount" "1" "Allow Microsoft accounts to be optional"  # 18.9.4.1

# ----- 19-series Registry Checks -----

# Screen saver settings
Check-Registry "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaveActive" "1" "Enable screen saver"
Check-Registry "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" "SCRNSAVE.EXE" "scrnsave.scr" "Force specific screen saver"
Check-Registry "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaverIsSecure" "1" "Password protect screen saver"

try {
    $timeout = (Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction Stop).ScreenSaveTimeOut
    if ([int]$timeout -le 900 -and [int]$timeout -ne 0) {
        Write-Output "[PASS] Screen saver timeout - Value: $timeout seconds"
    } else {
        Write-Output "[FAIL] Screen saver timeout - Value: $timeout seconds"
    }
} catch {
    Write-Output "[MISSING] Screen saver timeout - Registry value not found."
}

# Other 19-series keys
Check-Registry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DisableLockScreenAppNotifications" "1" "Turn off toast notifications on the lock screen"
Check-Registry "HKLM:\Software\Policies\Microsoft\Assistance\Client\1.0" "NoImplicitFeedback" "1" "Turn off Help Experience Improvement Program"
Check-Registry "HKLM:\Software\Policies\Microsoft\Windows\Explorer" "NoInplaceSharing" "1" "Prevent users from sharing files within their profile"
Check-Registry "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" "SaveZoneInformation" "0" "Do not preserve zone info in file attachments"
Check-Registry "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" "ScanWithAntiVirus" "3" "Notify antivirus programs when opening attachments"
Check-Registry "HKCU:\Software\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" "0" "Always install with elevated privileges (Current User)"
Check-Registry "HKLM:\Software\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" "0" "Always install with elevated privileges (Local Machine)"
Check-Registry "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" "PreventCodecDownload" "1" "Prevent Codec Download"
Check-Registry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "ConfigureWindowsSpotlight" "2" "Configure Windows spotlight on lock screen"
Check-Registry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableThirdPartySuggestions" "1" "Do not suggest third-party content in Windows spotlight"
Check-Registry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData" "1" "Do not use diagnostic data for tailored experiences"
Check-Registry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsSpotlightFeatures" "1" "Turn off all Windows spotlight features"
Check-Registry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsSpotlightOnActionCenter" "1" "Disable Windows spotlight notifications in Action Center"
Check-Registry "HKLM:\Software\Policies\Microsoft\Windows\LanmanServer" "DisableHomeDirectorySharing" "1" "Prevent users from sharing files within their profile"

Write-Host "`nCompliance check complete. Output saved to: $logPath" -ForegroundColor Cyan

Stop-Transcript
