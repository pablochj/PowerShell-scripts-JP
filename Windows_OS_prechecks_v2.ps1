# =================================================================================================
# Description : Windows pre-check script 
# =================================================================================================

# -----------------------------
# Privacy / Sharing Controls
# -----------------------------
# If enabled, the report will include potentially identifying environment details.
# Keep this disabled for shared/public versions.
$IncludeSensitiveReportFields = $false

# Optional placeholders for environment-specific infrastructure.
$ApprovedSaltMasters = @(
    @{ Host = '<salt_master_1>'; Port = 4505 },
    @{ Host = '<salt_master_2>'; Port = 4505 }
)

$ApprovedWUServers = @(
    '<wu_server_1>',
    '<wu_server_2>',
    '<wu_server_3>'
)

# Report/log locations use ProgramData instead of a user-specific or root drive path.
$ReportRoot = Join-Path $env:ProgramData 'SecurityPrecheck'
$null = New-Item -Path $ReportRoot -ItemType Directory -Force
$ReportPath = Join-Path $ReportRoot ('prechecks_{0}.txt' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
$TSMBackupCheckTxt = Join-Path $ReportRoot 'BackupCheck.txt'

# Initialize global variables
$Global:ReportTable = @()
$Global:NumberOfFailed = 0
$Global:BackupClientVersion = ''
$Global:FailedNr = 0
$Global:WarningNr = 0

$ErrorActionPreference = 'SilentlyContinue'
$NowDate = Get-Date
$Hostname = hostname
$User = $Env:UserName
$Domain = $Env:UserDomain
$OSversionLong = (Get-CimInstance Win32_OperatingSystem).Caption
$SkipBackupCheck = 0

$WSUSServerAddress = $null
$WSUSReportingServer = $null
$UseWUServerValue = $null
$WSUSConnectivity = $null
$Server = $null
$Port = 0
$NumberOfUpdates = 0
$DownloadSize = 0
$Counter = 1

# Initialize objects used by the script
$Searcher = New-Object -ComObject Microsoft.Update.Searcher
$List = New-Object System.Collections.Generic.List[System.String]

# Update output buffer size to prevent clipping in console output.
if ($Host -and $Host.UI -and $Host.UI.RawUI) {
    $rawUI = $Host.UI.RawUI
    $oldSize = $rawUI.BufferSize
    $typeName = $oldSize.GetType().FullName
    $newSize = New-Object $typeName (500, $oldSize.Height)
    $rawUI.BufferSize = $newSize
}

Clear-Host

# Search updates
$Criteria = "IsInstalled=0 and Type='Software' and IsHidden=0"
Write-Host ''
Write-Host 'Searching for updates. Please wait...'
$SearchResult = $Searcher.Search($Criteria).Updates
$NumberOfUpdates = $SearchResult.Count

if ($NumberOfUpdates -eq 0) {
    $NumberOfUpdatesResult = 'WARNING'
    $NumberOfUpdatesComment = 'No applicable updates'
}
elseif ($null -eq $NumberOfUpdates) {
    $NumberOfUpdatesResult = 'FAILED'
    $NumberOfUpdatesComment = 'Check update server configuration'
}
else {
    $NumberOfUpdatesResult = 'PASSED'
    $NumberOfUpdatesComment = ''
}

foreach ($WinUpdate in $SearchResult) {
    $Title = $WinUpdate.Title
    $Size = [System.Math]::Round($WinUpdate.MaxDownloadSize / 1GB, 2)
    $List.Add("$Counter. $Title ($Size GB)")
    $DownloadSize += $Size
    $Counter += 1
}
$UpdateList = $List.ToArray()

# Drive C check
$Disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType = '3'"
foreach ($disk in $Disks | Where-Object { $_.DeviceID -eq 'C:' }) {
    $DiskSize = [math]::Round($disk.Size / 1GB, 2)
    $DiskFree = [math]::Round($disk.FreeSpace / 1GB, 2)
    $Drive = $disk.DeviceID
}

$Buffer = 10
$BufferDownloadSize = $Buffer + $DownloadSize
if ($DiskFree -ge $BufferDownloadSize) {
    $DiskResult = 'PASSED'
    $DiskComment = "${BufferDownloadSize}GB (${Buffer}GB + update size) or more free"
}
else {
    $DiskResult = 'FAILED'
    $DiskComment = "Less than ${BufferDownloadSize}GB (${Buffer}GB + update size) free"
}

# Backup client checks (genericized labels for sharable template)
$BackupClientPath = 'C:\Program Files\BackupClient\client\backup.exe'
$BackupClientOpt1 = 'C:\Program Files\BackupClient\client\day.opt'
$BackupClientOpt2 = 'C:\Program Files\BackupClient\client\client.opt'

try { $BackupClientVersion = (Get-Item $BackupClientPath).VersionInfo.ProductVersion } catch {}
if (!$BackupClientVersion) { $BackupClientVersion = 'Backup client not installed' }

if (Test-Path (Split-Path $BackupClientPath)) {
    $Path = $BackupClientPath
    if (Test-Path $BackupClientOpt1) {
        $arg = '"' + $BackupClientOpt1 + '"'
        $BackupResult = 'PASSED'
        $BackupComment = ''
    }
    elseif (Test-Path $BackupClientOpt2) {
        $arg = '"' + $BackupClientOpt2 + '"'
        $BackupResult = 'PASSED'
        $BackupComment = ''
    }
    else {
        $BackupComment = 'Missing backup client option file'
        $BackupResult = 'INFO ONLY'
        $BackupClientVersion = ''
        $SkipBackupCheck = 1
    }
}
else {
    $BackupComment = 'Backup client home folder does not exist'
    $BackupResult = 'INFO ONLY'
    $BackupClientVersion = ''
    $SkipBackupCheck = 1
}

# Backup freshness checks (genericized)
if ($SkipBackupCheck -eq 0) {
    Remove-Item $TSMBackupCheckTxt -ErrorAction SilentlyContinue
    $app = Start-Process -FilePath $Path -ArgumentList "query files -optfile=${arg}" -RedirectStandardOutput $TSMBackupCheckTxt -PassThru
    Start-Sleep 20
    Stop-Process -Id $app.Id -Force -ErrorAction SilentlyContinue
    if (Test-Path $TSMBackupCheckTxt) {
        if ((Get-Content $TSMBackupCheckTxt).Length -gt 0) {
            # SystemState equivalent
            $BackupDateUnformatted = Get-Content $TSMBackupCheckTxt |
                ForEach-Object { "$(($_.Split(' ', [StringSplitOptions]'RemoveEmptyEntries')[1,2,4,5]))" } |
                Select-String -Pattern 'SystemState' |
                ForEach-Object { "$(($_ -split ' ')[0..1])" }

            if ($null -ne $BackupDateUnformatted) {
                $BackupDate = [datetime]"$BackupDateUnformatted"
                $deltaDays = (New-TimeSpan -Start $BackupDate -End $NowDate).Days
                if ($deltaDays -gt 1) {
                    $BackupSystemDate = "$BackupDate"
                    $BackupSystemResult = 'INFO ONLY'
                    $BackupSystemComment = $deltaDays
                }
                else {
                    $BackupSystemDate = "$BackupDate"
                    $BackupSystemResult = 'PASSED'
                    $BackupSystemComment = $deltaDays
                }
            }
            else {
                $BackupSystemDate = ''
                $BackupSystemResult = 'INFO ONLY'
                $BackupSystemComment = 'No system backup found'
            }

            # Drive C equivalent
            $BackupDateUnformatted = Get-Content $TSMBackupCheckTxt |
                ForEach-Object { "$(($_.Split(' ', [StringSplitOptions]'RemoveEmptyEntries')[1,2,4,5]))" } |
                Select-String -Pattern 'c\$' |
                ForEach-Object { "$(($_ -split ' ')[0..1])" }

            if ($null -ne $BackupDateUnformatted) {
                $BackupDate = [datetime]"$BackupDateUnformatted"
                $backupDays = (New-TimeSpan -Start $BackupDate -End $NowDate).Days
                if ($backupDays -gt 1) {
                    $BackupDriveCDate = "$BackupDate"
                    $BackupDriveCResult = 'INFO ONLY'
                    $BackupDriveCComment = "$backupDays days since last backup"
                }
                else {
                    $BackupDriveCDate = "$BackupDate"
                    $BackupDriveCResult = 'PASSED'
                    $BackupDriveCComment = "$backupDays days since last backup"
                }
            }
            else {
                $BackupDriveCDate = ''
                $BackupDriveCResult = 'WARNING'
                $BackupDriveCComment = 'Unable to obtain backup date'
            }
        }
        else {
            $BackupSystemDate = ''
            $BackupSystemResult = 'INFO ONLY'
            $BackupSystemComment = "Empty $TSMBackupCheckTxt file"
            $BackupDriveCDate = ''
            $BackupDriveCResult = 'INFO ONLY'
            $BackupDriveCComment = "Empty $TSMBackupCheckTxt file"
        }
    }
    else {
        $BackupSystemDate = ''
        $BackupSystemResult = 'INFO ONLY'
        $BackupSystemComment = "Missing $TSMBackupCheckTxt file"
        $BackupDriveCDate = ''
        $BackupDriveCResult = 'INFO ONLY'
        $BackupDriveCComment = "Missing $TSMBackupCheckTxt file"
    }
}
else {
    $BackupSystemDate = ''
    $BackupSystemResult = 'INFO ONLY'
    $BackupSystemComment = 'Backup client not installed/configured'
    $BackupDriveCDate = ''
    $BackupDriveCResult = 'INFO ONLY'
    $BackupDriveCComment = 'Backup client not installed/configured'
}

# Uptime
$currentdate = Get-Date
$a = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$BOOT_TIME = [Management.ManagementDateTimeConverter]::ToDateTime($a)
$TIMESPAN = $currentdate - $BOOT_TIME
$uptime = '{0:00}d {1:00}h {2:00}m {3:00}s' -f $TIMESPAN.Days, $TIMESPAN.Hours, $TIMESPAN.Minutes, $TIMESPAN.Seconds
$uptimeComment = 'INFO ONLY'

# CPU Utilisation
$CPU_AVG = Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average | ForEach-Object { $_.Average }
if ($CPU_AVG -gt 80) {
    $CPU_UTIL = "${CPU_AVG}%"
    $CPUResult = 'INFO ONLY'
    $CPUComment = 'Utilization in Red'
}
else {
    $CPU_UTIL = "${CPU_AVG}%"
    $CPUResult = 'INFO ONLY'
    $CPUComment = 'Utilization in Green'
}

# Memory Utilisation
$Memory_PC = Get-CimInstance Win32_OperatingSystem | ForEach-Object { ((($_.TotalVisibleMemorySize - $_.FreePhysicalMemory) * 100) / $_.TotalVisibleMemorySize) }
if ($Memory_PC -le 80) {
    $Memory = '{0:n2}' -f $Memory_PC
    $MemoryResult = 'INFO ONLY'
    $MemoryComment = 'Utilization in Green'
}
elseif ($Memory_PC -gt 80 -and $Memory_PC -le 90) {
    $Memory = "${Memory_PC}%"
    $MemoryResult = 'INFO ONLY'
    $MemoryComment = 'Utilization in Amber'
}
else {
    $Memory = "${Memory_PC}%"
    $MemoryResult = 'INFO ONLY'
    $MemoryComment = 'Utilization in Red'
}

# Services
$AutoServices = @()
$AutoServicesList = ''
$ExcludedServices = 'RemoteRegistry','sppsvc','TrustedInstaller','MapsBroker','IaasVmProvider','WbioSrvc','VSS','gupdate','clr_optimization_','ShellHWDetection','CDPSvc','tiledatamodelsvc'
$StoppedServices = (Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' }).Name
foreach ($StoppedService in $StoppedServices) {
    if (!($ExcludedServices -match $StoppedService)) {
        if (($StoppedService -notlike 'OneSyncSvc*') -and ($StoppedService -notlike 'CDPUserSvc*')) {
            $AutoServices += $StoppedService
            $AutoServicesList += $StoppedService + ';'
        }
    }
}
if ($AutoServices.Count -gt 0) {
    $AutoServicesCount = $AutoServices.Count
    $AutoServicesResult = 'WARNING'
    # Avoid exposing individual service names in shared output.
    $AutoServicesComment = if ($IncludeSensitiveReportFields) { $AutoServicesList } else { 'Stopped automatic services detected (names hidden in shared mode)' }
}
else {
    $AutoServicesCount = $AutoServices.Count
    $AutoServicesResult = 'PASSED'
    $AutoServicesComment = ''
}

# Persistent Routes
$routescount = (Get-CimInstance -ClassName Win32_IP4PersistedRouteTable).Count
if ($routescount -gt 0) {
    $Routes = ''
    $RoutesResult = 'PASSED'
    $RouteComment = "Found $routescount static routes"
}
else {
    $Routes = ''
    $RoutesResult = 'INFO ONLY'
    $RouteComment = 'No static routes found'
}

# Network configuration (values hidden by default in shared mode)
$GC = (Get-CimInstance -ClassName Win32_IP4RouteTable | Where-Object { $_.Mask -eq '0.0.0.0' }).NextHop
$CFN = (Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true -and $_.DefaultIPGateway -eq "$GC" }).IPAddress[0]
$IFN = (Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true -and $_.DefaultIPGateway -ne "$GC" }).IPAddress[0]

if (($GC.Substring(0, $GC.LastIndexOf('.'))) -match ($CFN.Substring(0, $CFN.LastIndexOf('.')))) {
    $GatewayResult = 'PASSED'
    $GatewayComment = ''
}
else {
    $GatewayResult = 'WARNING'
    $GatewayComment = 'Primary interface does not match gateway network'
}

if ($CFN -like '169.*') {
    $CFNResult = 'WARNING'
    $CFNComment = 'No static IP found'
}
else {
    $CFNResult = 'PASSED'
    $CFNComment = ''
}

if ($IFN -like '169.*') {
    $IFNResult = 'WARNING'
    $IFNComment = 'No static IP found'
}
else {
    $IFNResult = 'PASSED'
    $IFNComment = ''
}

# Check RDP
$RDP = netstat -ano | findstr /C:'TCP    0.0.0.0:3389'
if ($null -ne $RDP) {
    $RDPValue = 'Listening'
    $RDPResult = 'PASSED'
    $RDPComment = ''
}
else {
    $RDPValue = ''
    $RDPResult = 'FAILED'
    $RDPComment = 'RDP not listening on port 3389'
}

$RDPService = (Get-Service -Name TermService).Status
if ($RDPService -eq 'Running') {
    $RDPServiceResult = 'PASSED'
    $RDPServiceComment = ''
}
else {
    $RDPServiceResult = 'FAILED'
    $RDPServiceComment = 'RDP service not running'
}

# Check domain connection
$osInfo = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
if ($osInfo -eq 2) {
    $DomainTest = ''
    $DomainTestResult = 'INFO ONLY'
    $DomainTestComment = 'This is a domain controller'
}
else {
    if (Test-ComputerSecureChannel) {
        $DomainTest = 'True'
        $DomainTestResult = 'PASSED'
        $DomainTestComment = ''
    }
    else {
        $DomainTest = 'True'
        $DomainTestResult = 'FAILED'
        $DomainTestComment = 'Could not validate domain connection'
    }
}

# Check disk health
$osver = [System.Environment]::OSVersion.Version.Major
if ($osver -ge 10) {
    $diskhealth = 0
    $diskonline = 0
    $disktests = Get-DiskStorageNodeView
    if ($disktests) {
        foreach ($disk in $disktests) {
            if ($disk.HealthStatus -ne 'Healthy') { $diskhealth++ }
            if ($disk.OperationalStatus -ne 'Online') { $diskonline++ }
        }
        if (($diskhealth -eq 0) -and ($diskonline -eq 0)) {
            $DiskStatus = 'All Good'
            $DiskStatusResult = 'PASSED'
            $DiskStatusComment = ''
        }
        elseif (($diskhealth -ne 0) -and ($diskonline -eq 0)) {
            $DiskStatus = 'Not good'
            $DiskStatusResult = 'WARNING'
            $DiskStatusComment = 'There is at least one disk not healthy'
        }
        elseif (($diskhealth -eq 0) -and ($diskonline -ne 0)) {
            $DiskStatus = 'Not good'
            $DiskStatusResult = 'WARNING'
            $DiskStatusComment = 'There is at least one disk not online'
        }
        else {
            $DiskStatus = 'Not good'
            $DiskStatusResult = 'WARNING'
            $DiskStatusComment = 'There is at least one disk not online/healthy'
        }
    }
    else {
        $DiskStatus = 'Unknown'
        $DiskStatusResult = 'INFO ONLY'
        $DiskStatusComment = 'Could not check disks'
    }
}
else {
    $offlinedisks = 'list disk' | diskpart | Where-Object { $_ -match 'Offline' }
    if ($offlinedisks) {
        $DiskStatus = 'Not good'
        $DiskStatusResult = 'WARNING'
        $DiskStatusComment = 'There is at least one disk not online'
    }
    else {
        $DiskStatus = 'All Good'
        $DiskStatusResult = 'PASSED'
        $DiskStatusComment = ''
    }
}

# Configuration management task check (genericized label)
$ConfigTask = Get-ScheduledTask -TaskName '*config*'
if ($ConfigTask) {
    $ConfigTaskValue = 'Installed'
    $ConfigTaskResult = 'PASSED'
    $ConfigTaskComment = ''
}
else {
    $ConfigTaskValue = 'Not Installed'
    $ConfigTaskResult = 'WARNING'
    $ConfigTaskComment = 'Configuration task was not found'
}

if ($ConfigTaskResult -eq 'PASSED') {
    $ConfigTaskLastRun = (Get-ScheduledTask -TaskName '*config*' | Get-ScheduledTaskInfo).LastRunTime
    if ((New-TimeSpan -Start $ConfigTaskLastRun -End $NowDate).Days -gt 1) {
        $ConfigTaskLastRun = (New-TimeSpan -Start $ConfigTaskLastRun -End $NowDate).Days
        $ConfigLastRunResult = 'WARNING'
        $ConfigLastRunComment = "Configuration task did not run in the past ${ConfigTaskLastRun} days"
    }
    else {
        $ConfigLastRunResult = 'PASSED'
        $ConfigTaskLastRun = 'Good'
        $ConfigLastRunComment = 'Recent configuration task execution detected'
    }
}
else {
    $ConfigTaskLastRun = ''
    $ConfigLastRunResult = ''
    $ConfigLastRunComment = ''
}

# Check for pending reboot
try {
    $PendingReboot = $false
    $HKLM = [UInt32]'0x80000002'
    $WMI_Reg = [WMIClass]"\\$Hostname\root\default:StdRegProv"

    if ($WMI_Reg) {
        if (($WMI_Reg.EnumKey($HKLM,'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\')).sNames -contains 'RebootPending') { $PendingReboot = $true }
        if (($WMI_Reg.EnumKey($HKLM,'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\')).sNames -contains 'RebootRequired') { $PendingReboot = $true }
        if (($WMI_Reg.EnumKey($HKLM,'SYSTEM\CurrentControlSet\Control\Session Manager\')).sNames -contains 'PendingFileRenameOperations') { $PendingReboot = $true }

        $CCMNamespace = Get-CimInstance -Namespace ROOT\CCM\ClientSDK -ClassName __NAMESPACE -ErrorAction Ignore
        if ($CCMNamespace) {
            try {
                if (([WmiClass]"\\$Hostname\ROOT\CCM\ClientSDK:CCM_ClientUtilities").DetermineIfRebootPending().RebootPending -eq $true) {
                    $PendingReboot = $true
                }
            } catch {}
        }

        if ($PendingReboot -eq $true) {
            $PendingRebootValue = 'TRUE'
            $PendingRebootResult = 'INFO ONLY'
            $PendingRebootComment = 'There is a reboot pending'
        }
        else {
            $PendingRebootValue = 'FALSE'
            $PendingRebootResult = 'INFO ONLY'
            $PendingRebootComment = ''
        }
    }
}
catch {
    Write-Error $_.Exception.Message
}
finally {
    $WMI_Reg = $null
    $CCMNamespace = $null
}

# Virtualization tools check (genericized comments)
$VmToolsPath = 'C:\Program Files\VirtualizationTools\toolcmd.exe'
$VmToolsServiceName = 'VMTools'
$vmToolsVer = $null
try {
    if (Test-Path $VmToolsPath) {
        $vmToolsVer = & $VmToolsPath -v | Out-String
    }
} catch {}

if ($null -ne $vmToolsVer) {
    $vmToolsVer = $vmToolsVer.Split('(')[0]
    $vmToolsSrv = (Get-Service $VmToolsServiceName).Status
    if ($vmToolsSrv -eq 'Running') {
        $vmwarevalue = $vmToolsSrv
        $vmwareresult = 'PASSED'
        $vmwarecomment = "Version ${vmToolsVer}"
    }
    else {
        $vmwarevalue = $vmToolsSrv
        $vmwareresult = 'WARNING'
        $vmwarecomment = 'Service not running'
    }
}
else {
    $vmwarevalue = ''
    $vmwareresult = 'WARNING'
    $vmwarecomment = 'Not installed'
}

# Configuration agent service check (genericized label)
$agentServiceName = 'config-agent'
$agentSrv = (Get-Service $agentServiceName).Status
if ($null -ne $agentSrv) {
    if ($agentSrv -eq 'Running') {
        $agentValue = $agentSrv
        $agentResult = 'PASSED'
        $agentComment = ''
    }
    else {
        $agentValue = $agentSrv
        $agentResult = 'WARNING'
        $agentComment = 'Service not running'
    }
}
else {
    $agentValue = $agentSrv
    $agentResult = 'WARNING'
    $agentComment = 'Service not found'
}

# Configuration agent connectivity (real internal IPs removed)
$AgentConnectivityResult = 'WARNING'
$AgentConnectivityComment = 'Connectivity check skipped in sanitized template. Configure ApprovedSaltMasters before use.'
foreach ($endpoint in $ApprovedSaltMasters) {
    try {
        if ($endpoint.Host -notmatch '^<') {
            $socket = New-Object Net.Sockets.TcpClient ($endpoint.Host, $endpoint.Port)
            if ($socket.Connected) {
                $AgentConnectivityResult = 'PASSED'
                $AgentConnectivityComment = ''
                $socket.Close()
                break
            }
        }
    } catch {}
}

# Check for CRITICAL events
$qDate = (Get-Date).AddHours(-8)
$qlogs = Get-WinEvent System | Where-Object { $_.LevelDisplayName -eq 'Critical' -and $_.TimeCreated -gt $qDate }
if ($qlogs) {
    $qcount = $qlogs.Count
    $criticallogsvalue = $qcount
    $criticallogsresult = 'WARNING'
    # Do not expose event messages in shared template.
    $criticallogscomment = if ($IncludeSensitiveReportFields) { ($qlogs | Select-Object -ExpandProperty Message) -join ' | ' } else { 'Critical events detected; detailed messages hidden in shared mode' }
}
else {
    $criticallogsvalue = '0'
    $criticallogsresult = 'PASSED'
    $criticallogscomment = ''
}

# Monitoring agent checks (genericized labels)
$legacyMonitoring = @()
if (Get-Service | Where-Object { $_.Name -match 'monitor' }) { $legacyMonitoring += 'Monitoring agent found; ' }
if ($legacyMonitoring) {
    $oldmonvalue = ''
    $oldmonresult = 'INFO ONLY'
    $oldmoncomment = $legacyMonitoring
}
else {
    $oldmonvalue = ''
    $oldmonresult = 'PASSED'
    $oldmoncomment = 'No legacy monitoring agents found'
}

function Test-RegistryValue {
    param(
        [Alias('PSPath')]
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [String]$Path,
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$Name,
        [Switch]$PassThru
    )
    process {
        if (Test-Path $Path) {
            $Key = Get-Item -LiteralPath $Path
            if ($Key.GetValue($Name, $null) -ne $null) {
                if ($PassThru) { Get-ItemProperty $Path $Name } else { $true }
            }
            else { $false }
        }
        else { $false }
    }
}

# Update server configuration checks (real infrastructure removed)
if (Test-RegistryValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate WUServer) {
    $WSUSServerAddress = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name WUServer).WUServer
    if (($WSUSServerAddress -notlike 'http*') -or ([string]::IsNullOrEmpty($WSUSServerAddress))) {
        $WSUSServerAddressStatus = 'bad'
        $WSUSServerAddressResult = 'FAILED'
        $WSUSServerAddressComment = 'Update server not configured'
    }
    else {
        try {
            $serverUri = [uri]$WSUSServerAddress
            $Server = $serverUri.Host
            $Port = if ($serverUri.Port -gt 0) { $serverUri.Port } else { 80 }
        } catch {
            $Server = $null
            $Port = 0
        }

        $WSUSServerAddressStatus = 'bad'
        $WSUSServerAddressResult = 'FAILED'
        $WSUSServerAddressComment = 'Update server not valid'

        if ($ApprovedWUServers -contains $Server) {
            $WSUSServerAddressResult = 'PASSED'
            $WSUSServerAddressComment = ''
        }
    }
    if ($WSUSServerAddressResult -eq 'PASSED') {
        $WSUSServerAddressStatus = 'good'
    }
}
else {
    $WSUSServerAddressStatus = 'bad'
    $WSUSServerAddressResult = 'FAILED'
    $WSUSServerAddressComment = 'Update server not configured'
}

if (Test-RegistryValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate WUStatusServer) {
    $WSUSReportingServer = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name WUStatusServer).WUStatusServer
    if (($WSUSReportingServer -notlike 'http*') -or ([string]::IsNullOrEmpty($WSUSReportingServer))) {
        $WSUSReportingServerResult = 'FAILED'
        $WSUSReportingServerComment = 'Check status server configuration'
    }
    else {
        $WSUSReportingServerResult = 'PASSED'
        $WSUSReportingServerComment = ''
    }
}
else {
    $WSUSReportingServerResult = 'FAILED'
    $WSUSReportingServerComment = 'Status server not configured'
}

if (Test-RegistryValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU UseWUServer) {
    $UseWUServerValue = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name UseWUServer).UseWUServer
    if ($UseWUServerValue -eq 1) {
        $UseWUServerValueResult = 'PASSED'
        $UseWUServerValueComment = ''
    }
    else {
        $UseWUServerValueResult = 'FAILED'
        $UseWUServerValueComment = 'Value is not set to 1'
    }
}
else {
    $UseWUServerValueResult = 'FAILED'
    $UseWUServerValueComment = 'UseWUServer not set'
}

if ($WSUSServerAddressStatus -eq 'bad') {
    $WSUSConnectivityResult = 'FAILED'
    $WSUSConnectivityComment = 'Check update server configuration'
}
else {
    try {
        $Socket = New-Object Net.Sockets.TcpClient ($Server, $Port)
        if ($Socket.Connected) {
            $WSUSConnectivityResult = 'PASSED'
            $WSUSConnectivityComment = ''
            $Socket.Close()
        }
        else {
            $WSUSConnectivityResult = 'FAILED'
            $WSUSConnectivityComment = if ($IncludeSensitiveReportFields) { "Test failed for port $Port on $Server" } else { 'Update server connectivity test failed' }
        }
    } catch {
        $WSUSConnectivityResult = 'FAILED'
        $WSUSConnectivityComment = if ($IncludeSensitiveReportFields) { "Test failed for port $Port on $Server" } else { 'Update server connectivity test failed' }
    }
    $Socket = $null
}

# Endpoint security agent version check (genericized label)
$EndpointSecurityBinary = 'C:\Program Files\EndpointSecurity\agent.exe'
try { $endpointSecVer = (Get-Item $EndpointSecurityBinary).VersionInfo.ProductVersion } catch {}
if ($endpointSecVer) {
    if ($endpointSecVer -lt 20) {
        $endpointSecResult = 'WARNING'
        $endpointSecComment = 'Upgrade client according to local standard'
    }
    else {
        $endpointSecResult = 'PASSED'
        $endpointSecComment = ''
    }
}
else {
    $endpointSecResult = 'WARNING'
    $endpointSecComment = 'Not found. Verify or install according to local standard'
}

# Check when server was last patched
$patchdate = (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
$patchyear = [int]$patchdate.ToString('yyyy')
$patchmonth = [int]$patchdate.ToString('MM')
if (($patchmonth -ge 1) -and ($patchmonth -le 3)) { $patchlevel2 = 'Q1' }
if (($patchmonth -ge 4) -and ($patchmonth -le 6)) { $patchlevel2 = 'Q2' }
if (($patchmonth -ge 7) -and ($patchmonth -le 9)) { $patchlevel2 = 'Q3' }
if (($patchmonth -ge 10) -and ($patchmonth -le 12)) { $patchlevel2 = 'Q4' }
$patchlevel = "${patchlevel2}${patchyear}"

function Add-ToTable1 {
    param($Var1, $Var2, $Var3, $Var4)
    $Result = '' | Select-Object Item, Value, Result, Comment
    $Result.Item = "$Var1"
    $Result.Value = "$Var2"
    $Result.Result = "$Var3"
    $Result.Comment = "$Var4"
    if ($Var3 -eq 'WARNING') { $Global:WarningNr++ }
    if ($Var3 -eq 'FAILED' -or $Var3 -eq 'ERROR') {
        $Global:FailedNr++
        $Global:NumberOfFailed += 1
    }
    $Global:ReportTable += $Result
}

function Mask-Value {
    param([string]$Value)
    if ($IncludeSensitiveReportFields) { return $Value }
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    return '<hidden in shared mode>'
}

function Create-Report {
    Write-Host ''
    Write-Host 'Patch Validation Report'
    Write-Host '--------------------------------------------------------------------------------------'
    Write-Host ''

    Add-ToTable1 'Date/Time' "$NowDate" 'INFO ONLY' ''
    Add-ToTable1 'Hostname' (Mask-Value "$Hostname") 'INFO ONLY' ''
    Add-ToTable1 'OS Version' "$OSversionLong" 'INFO ONLY' ''
    Add-ToTable1 'Logged on user' (Mask-Value "$User") 'INFO ONLY' ''
    Add-ToTable1 'Logged on domain' (Mask-Value "$Domain") 'INFO ONLY' ''
    Add-ToTable1 'Update Status Server' (Mask-Value "$WSUSReportingServer") $WSUSReportingServerResult $WSUSReportingServerComment
    Add-ToTable1 'Update UseServer' $UseWUServerValue $UseWUServerValueResult $UseWUServerValueComment
    Add-ToTable1 'Update Connectivity' $WSUSConnectivity $WSUSConnectivityResult $WSUSConnectivityComment
    Add-ToTable1 'Disk' 'SizeGB/FreeGB' '' ''
    Add-ToTable1 "$Drive" "$DiskSize/$DiskFree" "$DiskResult" "$DiskComment"
    Add-ToTable1 'DiskStatus' "$DiskStatus" "$DiskStatusResult" "$DiskStatusComment"
    Add-ToTable1 'Number of updates' $NumberOfUpdates $NumberOfUpdatesResult $NumberOfUpdatesComment
    Add-ToTable1 'Total updates size (GB)' $DownloadSize 'INFO ONLY' ''
    Add-ToTable1 'Server patch level' $patchlevel 'INFO ONLY' ''
    Add-ToTable1 'Uptime' "$uptime" "$uptimeComment" ''
    Add-ToTable1 'CPU Usage' "$CPU_UTIL" "$CPUResult" "$CPUComment"
    Add-ToTable1 'Memory Usage' "${Memory}%" "$MemoryResult" "$MemoryComment"
    Add-ToTable1 'Backup Client Version' "$BackupClientVersion" "$BackupResult" "$BackupComment"
    Add-ToTable1 'Backup' 'Date/Time' '' ''
    Add-ToTable1 '- System Backup' "$BackupSystemDate" "$BackupSystemResult" "$BackupSystemComment"
    Add-ToTable1 '- Drive C:' "$BackupDriveCDate" "$BackupDriveCResult" "$BackupDriveCComment"
    Add-ToTable1 'Pending Reboot' "$PendingRebootValue" "$PendingRebootResult" "$PendingRebootComment"
    Add-ToTable1 'StoppedServices' "$AutoServicesCount" "$AutoServicesResult" "$AutoServicesComment"
    Add-ToTable1 'PersistentRoutes' "$Routes" "$RoutesResult" "$RouteComment"
    Add-ToTable1 'Gateway' (Mask-Value "$GC") "$GatewayResult" "$GatewayComment"
    Add-ToTable1 'Primary Interface' (Mask-Value "$CFN") "$CFNResult" "$CFNComment"
    Add-ToTable1 'Secondary Interface' (Mask-Value "$IFN") "$IFNResult" "$IFNComment"
    Add-ToTable1 'RDP Port' "$RDPValue" "$RDPResult" "$RDPComment"
    Add-ToTable1 'RDP Service' "$RDPService" "$RDPServiceResult" "$RDPServiceComment"
    Add-ToTable1 'Domain Connection' "$DomainTest" "$DomainTestResult" "$DomainTestComment"
    Add-ToTable1 'ConfigurationTask' "$ConfigTaskValue" "$ConfigTaskResult" "$ConfigTaskComment"
    Add-ToTable1 'ConfigurationTaskLastRun' "$ConfigTaskLastRun" "$ConfigLastRunResult" "$ConfigLastRunComment"
    Add-ToTable1 'VirtualizationTools' "$vmwarevalue" "$vmwareresult" "$vmwarecomment"
    Add-ToTable1 'ConfigurationAgent' "$agentValue" "$agentResult" "$agentComment"
    Add-ToTable1 'ConfigurationAgentConnectivity' '' "$AgentConnectivityResult" "$AgentConnectivityComment"
    Add-ToTable1 'EndpointSecurity' "$endpointSecVer" "$endpointSecResult" "$endpointSecComment"
    Add-ToTable1 'CriticalSystemLogs' "$criticallogsvalue" "$criticallogsresult" "$criticallogscomment"
    Add-ToTable1 'LegacyMonitoring' "$oldmonvalue" "$oldmonresult" "$oldmoncomment"

    $ReportTable | Format-Table -HideTableHeaders -AutoSize -Wrap | Out-String -Stream |
        ForEach-Object {
            if ($_ -match 'warning') { [console]::ForegroundColor = 'yellow'; $_ }
            elseif ($_ -match 'failed') { [console]::ForegroundColor = 'red'; $_ }
            else { [console]::ForegroundColor = 'white'; $_ }
        }

    Write-Host ''
    Write-Host ''
    Write-Host ''
    Write-Host 'Warning messages should be fixed before/during change'
    Write-Host ''
    Write-Host "Failed:   $Global:FailedNr"
    Write-Host "Warnings: $Global:WarningNr"
    Write-Host ''
    Write-Host '--------------------------------------------------------------------------------------'
    Write-Host ''
    Write-Host 'List of updates to install'
    Write-Host ''
    if ($NumberOfUpdates -gt 0) { $UpdateList } else { Write-Host '**None**' }
    Write-Host ''
    Write-Host ''
    Write-Host '--------------------------------------------------------------------------------------'
    Write-Host ''
}

# Create the main report
Create-Report | Tee-Object -FilePath $ReportPath

if ($NumberOfFailed -eq 0) {
    Write-Host 'Pre-check completed with exit code 0.'
    Write-Host ''
    exit 0
}
else {
    Write-Host 'Pre-check completed with exit code 1.'
    Write-Host ''
    exit 1
}
