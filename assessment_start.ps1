#Requires -RunAsAdministrator
#description: It will analyze and dump security relevant information from the system to be analyzed later on
#EXAMPLE
# cd \win_audit\
# .\assessment_start.ps1
#author: Patrick Eisenschmidt, peisenschmidt@nviso.de, NVISO Germany
#changelog:
#0.1.1
##

$psmodules = @{}
$psmodules.Add('ActiveDirectory','RSAT-AD-PowerShell')
$psmodules.Add('GroupPolicy', 'gcmp')

function Print($msg, $status){
    # ERROR
    if ($status -eq 1){
        Write-Output "[!] ${msg}"
    }# Not good
    elseif ($status -eq 2){
        Write-Output "[-] ${msg}"
    }# Good
    else{
        Write-Output "[+] ${msg}"
    }
}

function Create-If-Not-Exist($path){
    if (Test-Path -PathType Container -Path $path) {
        return
    }
    mkdir $path
}

function Import-Or-Install($module){
    Print "Trying to import module ${module}"

    if (Get-Module -ListAvailable -Name $module) {
        Import-Module $module
        Print "Module ${module} imported successfully"
    } 
    else {
        Print "Module ${module} does not exist" 2
        Print "Trying to install the missing dependency: ${$psmodules.Get_Item($module)}" 2
        try{
            #install-module is for powershell gallery
            Import-Module ServerManager
		    Add-WindowsFeature -Name $psmodules.Get_Item($module) -IncludeAllSubFeature
            Print "Module installed successfully"

            Import-Module $module
            Print "Module ${module} imported successfully"
        }catch{
            Print "Module could not be installed and loaded!" 1
        }
    }
}

# Dumping IIS config
function Backup-IIS(){
    Print "Saving IIS config..."
    Create-If-Not-Exist ($path = ".\results")

    # Ensure to import the WebAdministration module
    # If IIS is installed this should be available
    try{
        Import-Module WebAdministration
    }catch{
        Print "IIS is not installed" 2
        "IIS is not installed" | Out-File $path\iis_not_installed
        break
    }
    Backup-WebConfiguration -Name iisbackup
    Move-Item $env:Windir\System32\inetsrv\backup\* $path
}

# Windows Update offline search.. takes some minutes!
function Windows-Update(){
    Print "Checking dependency: wsusscn2.cab"
    if (-Not (Test-Path -PathType Leaf -Path ".\scripts\wsusscn2.cab")) {
        Print "The dependency is not available and will be downloaded..." 2
        # bypass potential tls/ssl issues
        #[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
        $url = "http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab"
        try{
            Invoke-WebRequest $url -OutFile ".\scripts\wsusscn2.cab"
            Print "Dependency successfully downloaded"
        }catch{
            Print "The dependency could not be downloaded" 1
            return $null
        }
    }
    $Wsusscn2FilePath = "$PSScriptRoot\scripts\wsusscn2.cab"

    $UpdateSession = New-Object -ComObject Microsoft.Update.Session  
    $UpdateServiceManager  = New-Object -ComObject Microsoft.Update.ServiceManager  
    $UpdateService = $UpdateServiceManager.AddScanPackageService("Offline Sync Service", $Wsusscn2FilePath, 1)  
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()   
  
    Print "Searching for updates... `r`n"  
    $UpdateSearcher.ServerSelection = 3 
    $UpdateSearcher.IncludePotentiallySupersededUpdates = $true 
    $UpdateSearcher.ServiceID = $UpdateService.ServiceID.ToString()  
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0") 
    $Updates = $SearchResult.Updates  
    Set-Content $path\updates.log -Value ""
    if($Updates.Count -eq 0){  
        Add-Content $path\updates.log -value "There are no applicable updates."
        return $null  
    }  
    Print "List of applicable items on the machine when using wssuscan.cab: `r`n"  
    $i = 0
    foreach($Update in $Updates){   
        Add-Content $path\updates.log -value "$($i)> $($Update.Title)"
        $i++  
    }
}

# Running Winpeas and PrivescCheck
function EoP(){
    Print "Running EoP checks..."
    Create-If-Not-Exist ($path = ".\results\eop")
    # bypass potential tls/ssl issues
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

    #(New-Object System.Net.WebClient).DownloadString("https://gist.githubusercontent.com/S3cur3Th1sSh1t/d14c3a14517fd9fb7150f446312d93e0/raw/2318ef41f55e7e1a2172a2e67551201c24ee7681/Invoke-winPEAS.ps1")|IEX
    #Invoke-winPEAS "notcolor" | Out-File out.txt
    #Move-Item .\out.txt .\results\winpeas_live.log
    
    Print "Running winpeas"
    & .\scripts\peass\winPEAS\winPEASbat\winpeas.bat nocolor 2>&1 | Out-File $path\winpeas.log

    Print "Running PrivescCheck"
    try{
        (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1')|iex
    }catch{
        . .\scripts\PrivescCheck.ps1 "-Extended"
    }
    Invoke-PrivescCheck -Report "$path\PrivescCheck_$env:COMPUTERNAME" -Format TXT,CSV,HTML

}

# Running HardeningKitty benchmark
function Hardening(){
    Print "Fetching files for os hardening analyse..."
    Create-If-Not-Exist ($path = ".\results\hardening")

    . .\scripts\Invoke-HardeningKitty.ps1
    Invoke-HardeningKitty .\scripts\lists\finding_list_0x6d69636b_machine.csv -mode "Audit" -log "$path\report_0x6d69636b_machine_log.csv" -report "$path\report_0x6d69636b_machine_report.csv" .\scripts\AccessChk\accesschk64.exe
    Invoke-HardeningKitty .\scripts\lists\finding_list_0x6d69636b_user.csv -mode "Audit" -log "$path\report_0x6d69636b_user_log.csv" -report "$path\report_0x6d69636b_user_report.csv" .\scripts\AccessChk\accesschk64.exe
    Invoke-HardeningKitty .\scripts\lists\finding_list_cis_microsoft_windows_server_2019_machine.csv -mode "Audit" -log "$path\report_cis_19_machine_log.csv" -report "$path\report_cis_19_machine_report.csv" .\scripts\AccessChk\accesschk64.exe
    Invoke-HardeningKitty .\scripts\lists\finding_list_cis_microsoft_windows_server_2019_user.csv -mode "Audit" -log "$path\report_cis_19_user_log.csv" -report "$path\report_cis_19_user_report.csv" .\scripts\AccessChk\accesschk64.exe

}

function GPO($tmp_path){
    Print "Fetching GPOs..."
    Create-If-Not-Exist $tmp_path
    Create-If-Not-Exist ($path = ".\results\gpo")

    Print "Running Backup-GPO"
    # https://arnaudloos.com/2018/intro-to-policy-analyzer/
    Import-Or-Install "GroupPolicy"
    try{
        Backup-GPO -All -Path "${tmp_path}\gpo.backup" -ErrorAction SilentlyContinue
    }catch{
        Print "Current security context is not associated with an Active Directory domain or forest" 2
    }

    Print "Running LGPO *ignore the error here"
    #LGPO for Microsoft Security Compliance Toolkit
    try{
        & .\scripts\LGPO.exe /b $tmp_path
    }catch{}
    Move-Item "${tmp_path}\{*" $path
    Move-Item "${tmp_path}\gpo*" $path

    Print "GPresult"
    gpresult /scope computer /h $path\group-policy.html
}

function Registry(){
    Print "Fetching Registry..."
    Create-If-Not-Exist ($path = ".\results\registry")

    #reg export HKCR $path\HKCR.Reg /y
    #reg export HKCU $path\HKCU.Reg /y
    #reg export HKLM $path\HKLM.Reg /y
    #reg export HKU $path\HKU.Reg /y
    #reg export HKCC $path\HKCC.Reg /y

    Print "WinLogin"
    reg export "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" $path\hklm_winlogon.reg
    Print "TCP/IP"
    reg export "HKLM\System\CurrentControlSet\Services\Tcpip\parameters" $path\hklm_tcpip.reg
    Print "TCP/IP6"
    reg export "HKLM\System\CurrentControlSet\Services\Tcpip6\parameters" $path\hklm_tcpip6.reg
    Print "LSA"
    reg export "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" $path\hklm_lsa.reg
    Print "Secure Pipe Server"
    reg export "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers" $path\hklm_securepipeservers.reg
    Print "LanMan Print Services"
    reg export "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" $path\hklm_lanman.reg
    Print "Software CurrentVersion"
    reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" $path\hklm_currentversion.reg
    Print "Desktop Software Policies"
    reg export "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" $path\hkcu_desktoppolicy.reg
    Print "Event Log"
    reg export "HKLM\SYSTEM\CurrentControlSet\services\eventlog\Application" $path\hklm_event_app.reg
    reg export "HKLM\SYSTEM\CurrentControlSet\services\eventlog\Security" $path\hklm_event_security.reg
    reg export "HKLM\SYSTEM\CurrentControlSet\services\eventlog\System" $path\hklm_event_system.reg
    Print "Windows Update"
    reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /s  2>&1 | Out-File $path\windows_update.log
    Print "Terminal Services"
    reg export "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" $path\hklm_terminal.reg
}

function System(){
    Print "Fetching Systemindentifier..."
    Create-If-Not-Exist ($path = ".\results\system")

    Print "Scheduled Tasks"
    Get-ScheduledTask 2>&1 | Out-File $path\tasks.log
    
    Print "Computer Info"
    Get-ComputerInfo 2>&1 | Out-File $path\systeminfo.log
    
    Print "Hotfixes"
    Get-HotFix 2>&1 | Out-File $path\hotfix.log

    Print "Windows Updates"
    Windows-Update

    Print "Environment Variables"
    dir env: 2>&1 | Out-File $path\environment_variable.log
 
    Print "Drivers"
    driverquery /FO CSV /V 2>&1 | Out-File $path\drivers.log

    Print "Startup Files"
    Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List  2>&1 | Out-File $path\drivers.log

    . .\scripts\Get-AntivirusProduct.ps1 2>&1 | Out-File $path\av.log
    #Get-WmiObject -Namespace root\SecurityCenter -Class AntivirusProduct
    & cmd /c 'wmic /output:"$path\SecurityCenter-AV.xml" /NAMESPACE:\\root\SecurityCenter PATH AntiVirusProduct GET /format:rawxml'
	& cmd /c 'wmic /output:"$path\SecurityCenter-AV.txt" /NAMESPACE:\\root\SecurityCenter PATH AntiVirusProduct GET'
	& cmd /c 'wmic /output:"$path\SecurityCenter2-AV.xml" /NAMESPACE:\\root\SecurityCenter2 PATH AntiVirusProduct GET /format:rawxml'
	& cmd /c 'wmic /output:"$path\SecurityCenter2-AV.txt" /NAMESPACE:\\root\SecurityCenter2 PATH AntiVirusProduct GET '
	& cmd /c 'wmic /output:"$path\SecurityCenter-Spyware.xml" /NAMESPACE:\\root\SecurityCenter PATH AntiSpywareProduct GET /format:rawxml'
	& cmd /c 'wmic /output:"$path\SecurityCenter-Spyware.txt" /NAMESPACE:\\root\SecurityCenter PATH AntiSpywareProduct GET '
	& cmd /c 'wmic /output:"$path\SecurityCenter2-Spyware.xml" /NAMESPACE:\\root\SecurityCenter2 PATH AntiSpywareProduct GET /format:rawxml'
	& cmd /c 'wmic /output:"$path\SecurityCenter2-Spyware.txt" /NAMESPACE:\\root\SecurityCenter2 PATH AntiSpywareProduct GET '
	& cmd /c 'wmic /output:"$path\SecurityCenter-Firewall.xml" /NAMESPACE:\\root\SecurityCenter PATH FirewallProduct GET /format:rawxml'
	& cmd /c 'wmic /output:"$path\SecurityCenter-Firewall.txt" /NAMESPACE:\\root\SecurityCenter PATH FirewallProduct GET '
	& cmd /c 'wmic /output:"$path\SecurityCenter2-Firewall.xml" /NAMESPACE:\\root\SecurityCenter2 PATH FirewallProduct GET /format:rawxml'
	& cmd /c 'wmic /output:"$path\SecurityCenter2-Firewall.txt" /NAMESPACE:\\root\SecurityCenter2 PATH FirewallProduct GET '
	
}

function Users(){
    Print "Fetching Users..."
    Create-If-Not-Exist ($path = ".\results\users")
    Import-Or-Install "ActiveDirectory"

    Print "Local Users"
    Out-File $path\localuser.log
    foreach ($user in (get-wmiobject Win32_UserAccount -filter 'LocalAccount=TRUE')){
        $username = ($user | select-object -ExpandProperty name)
        $username | Out-File -Append $path\localuser.log
        Get-LocalUser -Name $username | select * | Out-File -Append $path\localuser.log
        .\scripts\AccessChk\accesschk64.exe $username -a * | Out-File -Append $path\localuser.log
    }
    
    Print "Local Groups"
    Get-LocalGroup 2>&1 | Out-File $path\localgroups.log

    Print "Local Administrators"
    Get-LocalGroupMember -Group Administrators 2>&1 | Out-File $path\localadmins.log

    Print "Domain Admins"
    Get-ADGroupMember -Identity Administrators 2>&1 | Out-File $path\domainadmins.log

    Print "DOmain Trust"
    Get-ADTrust -Filter * 2>&1 | Out-File $path\domaintrust.log

    Print "Principle Group Membership"
    Get-ADPrincipalGroupMembership -Identity $env:USERNAME 2>&1 | Out-File $path\domaingroupmembership.log

    Print "Security Audit Policy"
    #import-module .\scripts\Get-SecurityAuditPolicy.ps1
    #Get-SecurityAuditPolicy 2>&1 | Out-File $path\domainadmins.log
    auditpol /backup 2>&1 | Out-File $path\auditpolicy.txt

    Print "Local Security Policy"
    secedit /export /cfg $path\security-policy.inf

    Print "Password Policy"
    net accounts  2>&1 | Out-File $path\password_policy.log
}

function Software(){
    Print "Fetching Software..."
    Create-If-Not-Exist ($path = ".\results\software")

    Print "Installed Products"
    Get-WmiObject -Class Win32_Product 2>&1 | Out-File $path\installed_products.log

    Print "Processes"
    Get-Process | select Name,Id,PriorityClass,FileVersion,Path,Company,ProductVersion,Description,HasExited,MainModule,Modules,ProcessName,StartInfo 2>&1 | Out-File $path\process.log

    Print "Service State"
    reg export "HKLM\SYSTEM\CurrentControlSet\Services" $path\hklm-ccs-services.txt
    net start  2>&1 | Out-File $path\running-services.log

    Print "Unquotes Service Paths"
    & cmd /c 'wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """ ' 2>&1 | Out-File $path\unquoted_service_paths.log
    
}

function Network(){
    Print "Fetching Networkinformation..."
    Create-If-Not-Exist ($path = ".\results\network")

    Print "Port Status"
    netstat -anbo  2>&1 | Out-File $path\user_directories.log

    Print "Network Adapter"
    Get-NetAdapter | select MacAddress,Status,LinkSpeed,MediaType,AdminStatus,MediaConnectionState,ifAlias,InterfaceAlias,ifIndex,ifDesc,ifName,LinkLayerAddress,Name,SystemName,AdminLocked,InterfaceDescription,PromiscuousMode 2>&1 | Out-File $path\adapter.log

    Print "Network Configuration"
    netsh dump 2>&1 | Out-File $path\network_configuration.log

    Print "Firewall Configuration"
    Import-Or-Install NetSecurity
    Get-NetFirewallRule 2>&1 | Out-File $path\firewall_configuration.log
}

function Files(){
    Print "Fetching Files..."
    Create-If-Not-Exist ($path = ".\results\files")

    Print "User folder"
    tree /a /f "C:\Users" 2>&1 | Out-File $path\user_directories.log

    Print "Shares"
    get-WmiObject -class Win32_Share -computer $env:COMPUTERNAME 2>&1 | Out-File $path\shares.log

    Print "Local Disks"
    "Get WmiObject`n" | Out-File $path\disks.log
    Get-WmiObject -Class Win32_logicaldisk 2>&1 | Out-File -Append $path\disks.log
    Get-Disk | select * 2>&1 | Out-File -Append $path\disks.log
    Get-PhysicalDisk | select * 2>&1 | Out-File -Append $path\disks.log
    Get-Partition | select * 2>&1 | Out-File -Append $path\disks.log

}
#---------------------------------------
# STARTING POINT
#---------------------------------------

Remove-Item '.\results' -Recurse
cls

$StartTime = Get-Date
$path = "C:\tmp"
Create-If-Not-Exist ".\results"

Print "Windows Build Review - Windows"
Print $StartTime
Print "Auditing..."

GPO $path
Hardening
EoP
Registry
System
Users
Software
Files
Network
Backup-IIS

Print "Creating a zip..."
Compress-Archive -Path .\results -DestinationPath .\results_$env:computername.zip -Force
Print ($(get-date) - $StartTime)

Print "Done!"