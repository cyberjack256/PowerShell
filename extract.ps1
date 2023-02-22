#Network Statistics Function
function Get-NetworkStatistics 
{ 
    $properties = ‘Protocol’,’LocalAddress’,’LocalPort’ 
    $properties += ‘RemoteAddress’,’RemotePort’,’State’,’ProcessName’,’PID’

    netstat -ano | Select-String -Pattern ‘\s+(TCP|UDP)’ | ForEach-Object {

        $item = $_.line.split(” “,[System.StringSplitOptions]::RemoveEmptyEntries)

        if($item[1] -notmatch ‘^\[::’) 
        {            
            if (($la = $item[1] -as [ipaddress]).AddressFamily -eq ‘InterNetworkV6’) 
            { 
               $localAddress = $la.IPAddressToString 
               $localPort = $item[1].split(‘\]:’)[-1] 
            } 
            else 
            { 
                $localAddress = $item[1].split(‘:’)[0] 
                $localPort = $item[1].split(‘:’)[-1] 
            } 

            if (($ra = $item[2] -as [ipaddress]).AddressFamily -eq ‘InterNetworkV6’) 
            { 
               $remoteAddress = $ra.IPAddressToString 
               $remotePort = $item[2].split(‘\]:’)[-1] 
            } 
            else 
            { 
               $remoteAddress = $item[2].split(‘:’)[0] 
               $remotePort = $item[2].split(‘:’)[-1] 
            } 

            New-Object PSObject -Property @{ 
                PID = $item[-1] 
                ProcessName = (Get-Process -Id $item[-1] -ErrorAction SilentlyContinue).Name 
                Protocol = $item[0] 
                LocalAddress = $localAddress 
                LocalPort = $localPort 
                RemoteAddress =$remoteAddress 
                RemotePort = $remotePort 
                State = if($item[0] -eq ‘tcp’) {$item[3]} else {$null} 
            } | Select-Object -Property $properties 
        } 
    } 
}

##### Process Tree Function ####

function Get-Tree_Process
{
    [CmdletBinding()]
    param([string]$ComputerName, [int]$IndentSize = 2)
    
    $indentSize   = [Math]::Max(1, [Math]::Min(12, $indentSize))
    $computerName = ($computerName, ".")[[String]::IsNullOrEmpty($computerName)]
    $processes    = Get-WmiObject Win32_Process -ComputerName $computerName
    $pids         = $processes | select -ExpandProperty ProcessId
    $parents      = $processes | select -ExpandProperty ParentProcessId -Unique
    $liveParents  = $parents | ? { $pids -contains $_ }
    $deadParents  = Compare-Object -ReferenceObject $parents -DifferenceObject $liveParents `
                  | select -ExpandProperty InputObject
    $processByParent = $processes | Group-Object -AsHashTable ParentProcessId
    
    function Write-ProcessTree($process, [int]$level = 0)
    {
        $id = $process.ProcessId
        $parentProcessId = $process.ParentProcessId
        $process = Get-Process -Id $id -ComputerName $computerName
        $indent = New-Object String(' ', ($level * $indentSize))
        $process `
        | Add-Member NoteProperty ParentId $parentProcessId -PassThru `
        | Add-Member NoteProperty Level $level -PassThru `
        | Add-Member NoteProperty IndentedName "$indent$($process.Name)" -PassThru 
        $processByParent.Item($id) `
        | ? { $_ } `
        | % { Write-ProcessTree $_ ($level + 1) }
    }

    $processes `
    | ? { $_.ProcessId -ne 0 -and ($_.ProcessId -eq $_.ParentProcessId -or $deadParents -contains $_.ParentProcessId) } `
    | % { Write-ProcessTree $_ }
}

#####    MAIN  #######

MKDIR D:\${Env:ComputerName}\
MKDIR D:\${Env:ComputerName}\INTERNET\
MKDIR D:\${Env:ComputerName}\JUMPLISTS\
MKDIR D:\${Env:ComputerName}\PROG\
MKDIR D:\${Env:ComputerName}\PROC\
MKDIR D:\${Env:ComputerName}\NETWORK\
MKDIR D:\${Env:ComputerName}\REGISTRY\

#######  ENVIRONMENTAL INFORMATION #######
##OS object parameters##
Get-CimInstance Win32_Operatingsystem | `
Select-Object Caption, InstallDate, ServicePackMajorVersion, OSArchitecture, BootDevice, BuildNumber, CSName | FL >> D:\${Env:ComputerName}\${Env:ComputerName}-OS_object_parameters.txt

#########   FILES AND FILE STRUCTURE    #########
# TREE STRUCTURE
Tree /F | fl >> D:\${Env:ComputerName}\${Env:ComputerName}-Tree_Folder_Structure.txt
#OPENED FILES
openfiles /query /fo table /v > D:\${Env:ComputerName}\${Env:ComputerName}-Openfiles.txt
#OPENED SHARES
## Opened Shares and Open Shares Access Permissions ##
Get-SmbShare -IncludeHidden >> D:\${Env:ComputerName}\Open_shares.txt
Get-SmbShareAccess -Name ADMIN$,C$,IPC$ |FL * >> D:\${Env:ComputerName}\${Env:ComputerName}-Open_shares.txt
#MAPPED DRIVES
Get-PSDrive >> D:\${Env:ComputerName}\${Env:ComputerName}-Mapped_drives.txt

#########   USERS   ##########
Get-WmiObject win32_LogonSession | ForEach-Object {$one =$_; $one.GetRelated('win32_Account') | Select-Object Domain, Name, SID, @{ Name = 'LogonType' ; Expression = { $one.LogonType } }} >> D:\${Env:ComputerName}\${Env:ComputerName}-Users.txt

#########   SCHEDULED TASKS AND RUNNING PROCESSES    #########
#SCHEDULED TASKS
schtasks /query /fo list /v >> D:\${Env:ComputerName}\PROC\${Env:ComputerName}-ScheduledTasks.txt
schtasks /query /fo csv /v >> D:\${Env:ComputerName}\PROC\${Env:ComputerName}-ScheduledTasks.csv
#RUNNING WINDOWS SERVICES
Get-Service | Where-Object {$_.status -eq "running"} | select-object Name, DisplayName, Status| Export-Csv D:\${Env:ComputerName}\${Env:ComputerName}-WinSvcs.csv -NoTypeInformation
#RUNNING PROCESSES
tasklist /svc >> D:\${Env:ComputerName}\PROC\${Env:ComputerName}-TaskList-Services.txt
tasklist /v >> D:\${Env:ComputerName}\PROC\${Env:ComputerName}-TaskList-Verbose.txt
tasklist /m >> D:\${Env:ComputerName}\PROC\${Env:ComputerName}-TaskList-Modules.txt
Get-WmiObject -class win32_process| select-object -property processname, ws, parentprocessid, processid, sessionid | Export-csv D:\${Env:ComputerName}\PROC\${Env:ComputerName}-Tasklist.txt
get-process | select Name, Description, ID, @{Label="MemoryUsage(KB)";Expression={($_.WS / 1KB)}}, @{Label="CPU Time(s)";Expression={($_.CPU)}}|export-csv D:\${Env:ComputerName}\PROC\${Env:ComputerName}-Tasklist.csv -NoTypeInformation
Get-Tree_Process >> D:\${Env:ComputerName}\PROC\${Env:ComputerName}-Tree_Process.txt
#AUTORUNS
D:\SysTools\autorunsc64.exe -accepteula -a * -c >> D:\${Env:ComputerName}\PROC\${Env:ComputerName}-autoruns.csv

#########   NETWORKING INFORMATION    #########
#IP INFO
ipconfig /all >> D:\${Env:ComputerName}\NETWORK\${Env:ComputerName}-IPInfo.txt
ipconfig /displaydns >> D:\${Env:ComputerName}\NETWORK\${Env:ComputerName}-IPInfo.txt
#ADDRESS RESOLUTION PROTOCOL
arp -a >> D:\${Env:ComputerName}\NETWORK\${Env:ComputerName}-ARPTable.txt
#COPY THE HOST FILE
copy-item -path C:\Windows\System32\drivers\etc\hosts -destination D:\${Env:ComputerName}\NETWORK\
#NETSTAT for established and listening network connections.
netstat -naob >> D:\${Env:ComputerName}\NETWORK\${Env:ComputerName}-Netstat.txt
#NETWORK STATISTICS
Get-NetworkStatistics | FT -AutoSize >> D:\${Env:ComputerName}\NETWORK\${Env:ComputerName}-NetworkStats.txt


#########   PROGRAMS   #########
#STARTUP PROGRAM LIST
get-wmiobject -class "Win32_StartupCommand" | select-object Name, command, User, Location | Export-Csv D:\${Env:ComputerName}\PROG\${Env:ComputerName}-StartupList.csv -NoTypeInformation
#GET INSTALLED PROGRAMS
WMIC Product List Full /format:csv >> D:\${Env:ComputerName}\PROG\${Env:ComputerName}-InstalledPrograms.txt
#Output Program Files Directory Structures
Get-ChildItem -Directory $env:ProgramFiles >> D:\${Env:ComputerName}\PROG\${Env:ComputerName}-ProgramFilesDirectories.txt
Get-ChildItem -Directory ${env:ProgramFiles(x86)} >> D:\${Env:ComputerName}\PROG\${Env:ComputerName}-ProgramFilesx86Directories.txt
#GET INSTALLED PATCHES
WMIC qfe list >> D:\${Env:ComputerName}\PROG\${Env:ComputerName}-InstalledPatches.txt
#Search for Flash
get-childitem $env:SystemRoot\SysWOW64\Macromed\Flash >> D:\${Env:ComputerName}\PROG\${Env:ComputerName}-Flash64bitHost.txt
get-childitem $env:SystemRoot\System32\Macromed\Flash >> D:\${Env:ComputerName}\PROG\${Env:ComputerName}-Flashx86Location.txt
#List file types from Users directory that may indicate malicious file along with NTUser file metadata.
$extensions="*.cmd","*.bat","*.vbs","*.js","*.com","*.exe","*.wsf","*.swf ","*.jar","*.dat"
Get-ChildItem -Recurse c:\Users -Include $extensions >> D:\${Env:ComputerName}\PROG\${Env:ComputerName}-FileTypesOfInterest.txt

#########   FIREWALL CONFIGURATION   #########
netsh advfirewall show allprofiles >> D:\${Env:ComputerName}\NETWORK\${Env:ComputerName}-FirewallConfig.txt
netsh advfirewall firewall show rule name=all type=dynamic >> D:\${Env:ComputerName}\NETWORK\${Env:ComputerName}-FirewallRules.txt
copy-item -path C:\Windows\system32\LogFiles\Firewall\pfirewall.log -Destination D:\${Env:ComputerName}\NETWORK\${Env:ComputerName}-pfirewall.log

#########   REGISTRY    #########
reg save HKLM\SYSTEM D:\${Env:ComputerName}\REGISTRY\${Env:ComputerName}-SYSTEM
reg save HKLM\SOFTWARE D:\${Env:ComputerName}\REGISTRY\${Env:ComputerName}-SOFTWARE
reg save HKLM\SAM D:\${Env:ComputerName}\REGISTRY\${Env:ComputerName}-SAM
#Dump available User registries separately.  Some may error out. Like the blank top line.
#First generate list of potential user registries.
reg query HKU > D:\${Env:ComputerName}\REGISTRY\HKU-list.txt
#Then cleanup the list.
(Get-Content D:\${Env:ComputerName}\REGISTRY\HKU-list.txt) -replace "HKEY_USERS\\","" >> D:\${Env:ComputerName}\REGISTRY\HKU-list.txt
#Now iterate through the list and save each key.
$RegistryUsers = Get-Content D:\${Env:ComputerName}\REGISTRY\HKU-list.txt
ForEach ($RegistryUser in $RegistryUsers)
{
reg save HKU\$RegistryUser D:\${Env:ComputerName}\REGISTRY\${Env:ComputerName}-$RegistryUser-NThive}

#########   WEB ARTIFACTS    #########
#Build list of user folders
Get-ChildItem -Directory c:\Users -Name >> D:\${Env:ComputerName}\INTERNET\${Env:ComputerName}-UserFolders.txt

#Iterate User profile folders and then grab each profile's WebCache folder.  
#At end of script b/c command shuts down certain services and processes.  Best if machine is restarted once the entire collection is finished. 
#May only need the taskkill for taskhost.exe command on certain systems.
net stop COMSysApp
taskkill /F /IM dllhost.exe
taskkill /F /IM taskhost.exe
taskkill /F /IM taskhostex.exe
Get-ChildItem -Directory c:\Users -Name >> D:\${Env:ComputerName}\INTERNET\${Env:ComputerName}-UserFolders.txt
$UserFolders = Get-Content  D:\${Env:ComputerName}\INTERNET\${Env:ComputerName}-UserFolders.txt
ForEach ($UserFolder in $UserFolders)
{
robocopy C:\Users\$UserFolder\AppData\Local\Microsoft\Windows\WebCache D:\${Env:ComputerName}\INTERNET\${Env:ComputerName}-$UserFolder\WebCache /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:D:\${Env:ComputerName}\INTERNET\${Env:ComputerName}-$UserFolder-WebCacheV01GrabLog.txt}
net start ComSysApp

#Grab Firefox SQLITE Files, if available, from each user profile.
$UserFolders = Get-Content D:\${Env:ComputerName}\INTERNET\${Env:ComputerName}-UserFolders.txt
ForEach ($UserFolder in $UserFolders)
{
robocopy C:\Users\$UserFolder\AppData\Roaming\Mozilla\Firefox\Profiles D:\${Env:ComputerName}\INTERNET\${Env:ComputerName}-$UserFolder\Firefox *.sqlite /S /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:D:\${Env:ComputerName}\INTERNET\${Env:ComputerName}-$UserFolder-FirefoxGrabLog.txt}
#Grab all Google Chrome data, if available, from each user profile.
$UserFolders = Get-Content D:\${Env:ComputerName}\INTERNET\${Env:ComputerName}-UserFolders.txt
ForEach ($UserFolder in $UserFolders)
{
robocopy "C:\Users\$UserFolder\AppData\Local\Google\Chrome\User Data" D:\${Env:ComputerName}\INTERNET\${Env:ComputerName}-$UserFolder\Chrome /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:D:\${Env:ComputerName}\INTERNET\${Env:ComputerName}-$UserFolder-ChromeGrabLog.txt}

#Grab Jump Lists for each user found on the system. Automatic and pinned(custom).
$UserFolders = Get-Content D:\${Env:ComputerName}\INTERNET\${Env:ComputerName}-UserFolders.txt
ForEach ($UserFolder in $UserFolders)
{
robocopy "C:\Users\$UserFolder\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" "D:\${Env:ComputerName}\JUMPLISTS\${Env:ComputerName}-$UserFolder\" /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:D:\${Env:ComputerName}\JUMPLISTS\${Env:ComputerName}-$UserFolder-jumplists.txt
robocopy "C:\Users\$UserFolder\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations" "D:\${Env:ComputerName}\JUMPLISTS\${Env:ComputerName}-$UserFolder\" /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:D:\${Env:ComputerName}\JUMPLISTS\${Env:ComputerName}-$UserFolder-jumplists.txt} 

#CONTENTS OF PREFETCH FOLDER
ls C:\Windows\Prefetch | select-object Name, FullName, CreationTime, LastAccessTime, LastWriteTime, Mode | Export-Csv D:\${Env:ComputerName}\${Env:ComputerName}-PreFetchFolder.csv -NoTypeInformation
#Copy prefetch folder contents
robocopy c:\windows\prefetch D:\${Env:ComputerName}\prefetch_grab /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:D:\${Env:ComputerName}\${Env:ComputerName}-PrefetchGrabLog.txt