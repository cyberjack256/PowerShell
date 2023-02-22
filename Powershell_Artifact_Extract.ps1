#Network Statistics Function
function Get-NetworkStatistics 
{ 
    $properties = ‘Protocol’,’LocalAddress’,’LocalPort’ 
    $properties += ‘RemoteAddress’,’RemotePort’,’State’,’ProcessName’,’PID’

    netstat -ano | Select-String -Pattern ‘\s+(TCP|UDP)’ | ForEach-Object {

        $item = $_.line.split(” “,[System.StringSplitOptions]::RemoveEmptyEntries)

        if($item[1] -notmatch ‘^\[::’) 
        {            
            if (($la = ($item[1] -as [ipaddress])).AddressFamily -eq ‘InterNetworkV6’) 
            { 
                $localAddress = $la.IPAddressToString 
                $localPort = $item[1].split(‘\]:’)[-1] 
            } 
            else 
            { 
                $localAddress = $item[1].split(‘:’)[0] 
                $localPort = $item[1].split(‘:’)[-1] 
            } 

            if (($ra = ($item[2] -as [ipaddress])).AddressFamily -eq ‘InterNetworkV6’) 
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
    $processes    = Get-WmiObject Win32_Process -ComputerName $computerName -Property Name, ProcessId, ParentProcessId
    $pids         = $processes | Select-Object -ExpandProperty ProcessId
    $parents      = $processes | Select-Object -ExpandProperty ParentProcessId -Unique
    $liveParents  = $parents | Where-Object { $pids -contains $_ }
    $deadParents  = Compare-Object -ReferenceObject $parents -DifferenceObject $liveParents `
    | Select-Object -ExpandProperty InputObject
    $processByParent = $processes | Group-Object -AsHashTable ParentProcessId
    
    function Write-ProcessTree($process, [int]$level = 0)
    {
        $id = $process.ProcessId
        $parentProcessId = $process.ParentProcessId
        $process = Get-Process -Id $id -ComputerName $computerName
        $indent = New-Object String(' ', ($level * $indentSize))
        $alive = $liveParents -contains $id
        $aliveStatus = if($alive){"Alive"}else{"Dead"}
        $parentProcess = $processes | Where-Object { $_.ProcessId -eq $parentProcessId }
        $parentName = if($parentProcess){$parentProcess.Name}else{"N/A"}
        $process `
        | Add-Member NoteProperty ProcessId $id -PassThru `
        | Add-Member NoteProperty ParentId $parentProcessId -PassThru `
        | Add-Member NoteProperty ParentName $parentName -PassThru `
        | Add-Member NoteProperty Alive $aliveStatus -PassThru `
        | Add-Member NoteProperty Level $level -PassThru `
        | Add-Member NoteProperty IndentedName "$indent$($process.Name)" -PassThru 
        $processByParent.Item($id) `
        | Where-Object { $_ } `
        | ForEach-Object { Write-ProcessTree $_ ($level + 1) }
    }

    $processes |
    Where-Object { $_.ProcessId -ne 0 -and ($_.ProcessId -eq $_.ParentProcessId -or $deadParents -contains $_.ParentProcessId) } |
    ForEach-Object { Write-ProcessTree $_ } |
    Select-Object ProcessId, IndentedName, ParentId, ParentName, Alive, Level
}

#####    MAIN  #######

## Create directories to store output files
MKDIR ${SYSTEMDRIVE}\${Env:ComputerName}\
MKDIR ${SYSTEMDRIVE}\${Env:ComputerName}\INTERNET\
MKDIR ${SYSTEMDRIVE}\${Env:ComputerName}\JUMPLISTS\
MKDIR ${SYSTEMDRIVE}\${Env:ComputerName}\PROG\
MKDIR ${SYSTEMDRIVE}\${Env:ComputerName}\PROC\
MKDIR ${SYSTEMDRIVE}\${Env:ComputerName}\NETWORK\
MKDIR ${SYSTEMDRIVE}\${Env:ComputerName}\REGISTRY\

#######  ENVIRONMENTAL INFORMATION #######
##OS object parameters##

## Collect information about the operating system and write it to a file
Get-CimInstance Win32_Operatingsystem | `
Select-Object Caption, InstallDate, ServicePackMajorVersion, OSArchitecture, BootDevice, BuildNumber, CSName | Format-List >> ${SYSTEMDRIVE}\${Env:ComputerName}\${Env:ComputerName}-OS_object_parameters.txt

#########   FILES AND FILE STRUCTURE    #########
# TREE STRUCTURE
## Generate a text file showing the directory tree structure and write it to a file
Get-ChildItem | Tree | Out-File -Encoding ascii ${SYSTEMDRIVE}\${Env:ComputerName}\${Env:ComputerName}-Tree_Folder_Structure.txt
#OPENED FILES
## List all open SMB shares and write it to a file
openfiles /query /fo table /v > ${SYSTEMDRIVE}\${Env:ComputerName}\${Env:ComputerName}-Openfiles.txt
#OPENED SHARES
## Opened Shares and Open Shares Access Permissions ##
Get-SmbShare -IncludeHidden >> ${SYSTEMDRIVE}\${Env:ComputerName}\Open_shares.txt
## List access permissions for specific SMB shares and write it to a file
Get-SmbShareAccess -Name ADMIN$,C$,IPC$ |Format-List * >> ${SYSTEMDRIVE}\${Env:ComputerName}\${Env:ComputerName}-Open_shares.txt
#MAPPED DRIVES
## List all mapped drives and write it to a file
Get-PSDrive >> ${SYSTEMDRIVE}\${Env:ComputerName}\${Env:ComputerName}-Mapped_drives.txt

#########   USERS   ##########
## Get infomration about all users currently logged in and write it to a file
Get-WmiObject win32_LogonSession | ForEach-Object {$one =$_; $one.GetRelated('win32_Account') | Select-Object Domain, Name, SID, @{ Name = 'LogonType' ; Expression = { $one.LogonType } }} >> ${SYSTEMDRIVE}\${Env:ComputerName}\${Env:ComputerName}-Users.txt

#########   SCHEDULED TASKS AND RUNNING PROCESSES    #########
#SCHEDULED TASKS
## List all scheduled tasks and write it to a CSV file
schtasks /query /fo list /v >> ${SYSTEMDRIVE}\${Env:ComputerName}\PROC\${Env:ComputerName}-ScheduledTasks.txt
schtasks /query /fo csv /v >> ${SYSTEMDRIVE}\${Env:ComputerName}\PROC\${Env:ComputerName}-ScheduledTasks.csv
#RUNNING WINDOWS SERVICES
## List all currently running Windows services and write it to a CSV file
Get-Service | Where-Object {$_.status -eq "running"} | select-object Name, DisplayName, Status| Export-Csv ${SYSTEMDRIVE}\${Env:ComputerName}\${Env:ComputerName}-WinSvcs.csv -NoTypeInformation
#RUNNING PROCESSES
tasklist /svc >> ${SYSTEMDRIVE}\${Env:ComputerName}\PROC\${Env:ComputerName}-TaskList-Services.txt
tasklist /v >> ${SYSTEMDRIVE}\${Env:ComputerName}\PROC\${Env:ComputerName}-TaskList-Verbose.txt
tasklist /m >> ${SYSTEMDRIVE}\${Env:ComputerName}\PROC\${Env:ComputerName}-TaskList-Modules.txt
Get-WmiObject -class win32_process| select-object -property processname, ws, parentprocessid, processid, sessionid | Export-csv ${SYSTEMDRIVE}\${Env:ComputerName}\PROC\${Env:ComputerName}-Tasklist.txt
get-process | Select-Object Name, Description, ID, @{Label="MemoryUsage(KB)";Expression={($_.WS / 1KB)}}, @{Label="CPU Time(s)";Expression={($_.CPU)}}|export-csv ${SYSTEMDRIVE}\${Env:ComputerName}\PROC\${Env:ComputerName}-Tasklist.csv -NoTypeInformation
Get-Tree_Process | Format-Table -AutoSize >> ${SYSTEMDRIVE}\${Env:ComputerName}\PROC\${Env:ComputerName}-Tree_Process.txt
#AUTORUNS
# ${SYSTEMDRIVE}\SysTools\autorunsc64.exe -accepteula -a * -c >> ${SYSTEMDRIVE}\${Env:ComputerName}\PROC\${Env:ComputerName}-autoruns.csv

#########   NETWORKING INFORMATION    #########
#IP INFO
ipconfig /all >> ${SYSTEMDRIVE}\${Env:ComputerName}\NETWORK\${Env:ComputerName}-IPInfo.txt
ipconfig /displaydns >> ${SYSTEMDRIVE}\${Env:ComputerName}\NETWORK\${Env:ComputerName}-IPInfo.txt
#ADDRESS RESOLUTION PROTOCOL
arp -a >> ${SYSTEMDRIVE}\${Env:ComputerName}\NETWORK\${Env:ComputerName}-ARPTable.txt
#COPY THE HOST FILE
copy-item -path C:\Windows\System32\drivers\etc\hosts -destination ${SYSTEMDRIVE}\${Env:ComputerName}\NETWORK\
#NETSTAT for established and listening network connections.
netstat -naob >> ${SYSTEMDRIVE}\${Env:ComputerName}\NETWORK\${Env:ComputerName}-Netstat.txt
#NETWORK STATISTICS
Get-NetworkStatistics | Format-Table -AutoSize >> ${SYSTEMDRIVE}\${Env:ComputerName}\NETWORK\${Env:ComputerName}-NetworkStats.txt


#########   PROGRAMS   #########
#STARTUP PROGRAM LIST
get-wmiobject -class "Win32_StartupCommand" | select-object Name, command, User, Location | Export-Csv ${SYSTEMDRIVE}\${Env:ComputerName}\PROG\${Env:ComputerName}-StartupList.csv -NoTypeInformation
#GET INSTALLED PROGRAMS
WMIC Product List Full /format:csv >> ${SYSTEMDRIVE}\${Env:ComputerName}\PROG\${Env:ComputerName}-InstalledPrograms.txt
#Output Program Files Directory Structures
Get-ChildItem -Directory $env:ProgramFiles >> ${SYSTEMDRIVE}\${Env:ComputerName}\PROG\${Env:ComputerName}-ProgramFilesDirectories.txt
Get-ChildItem -Directory ${env:ProgramFiles(x86)} >> ${SYSTEMDRIVE}\${Env:ComputerName}\PROG\${Env:ComputerName}-ProgramFilesx86Directories.txt
#GET INSTALLED PATCHES
WMIC qfe list >> ${SYSTEMDRIVE}\${Env:ComputerName}\PROG\${Env:ComputerName}-InstalledPatches.txt
#Search for Flash
get-childitem $env:SystemRoot\SysWOW64\Macromed\Flash >> ${SYSTEMDRIVE}\${Env:ComputerName}\PROG\${Env:ComputerName}-Flash64bitHost.txt
get-childitem $env:SystemRoot\System32\Macromed\Flash >> ${SYSTEMDRIVE}\${Env:ComputerName}\PROG\${Env:ComputerName}-Flashx86Location.txt
#List file types from Users directory that may indicate malicious file along with NTUser file metadata.
$extensions="*.cmd","*.bat","*.vbs","*.js","*.com","*.exe","*.wsf","*.swf ","*.jar","*.dat"
Get-ChildItem -Recurse c:\Users -Include $extensions >> ${SYSTEMDRIVE}\${Env:ComputerName}\PROG\${Env:ComputerName}-FileTypesOfInterest.txt

#########   FIREWALL CONFIGURATION   #########
netsh advfirewall show allprofiles >> ${SYSTEMDRIVE}\${Env:ComputerName}\NETWORK\${Env:ComputerName}-FirewallConfig.txt
netsh advfirewall firewall show rule name=all type=dynamic >> ${SYSTEMDRIVE}\${Env:ComputerName}\NETWORK\${Env:ComputerName}-FirewallRules.txt
copy-item -path C:\Windows\system32\LogFiles\Firewall\pfirewall.log -Destination ${SYSTEMDRIVE}\${Env:ComputerName}\NETWORK\${Env:ComputerName}-pfirewall.log

#########   REGISTRY    #########
reg save HKLM\SYSTEM ${SYSTEMDRIVE}\${Env:ComputerName}\REGISTRY\${Env:ComputerName}-SYSTEM
reg save HKLM\SOFTWARE ${SYSTEMDRIVE}\${Env:ComputerName}\REGISTRY\${Env:ComputerName}-SOFTWARE
reg save HKLM\SAM ${SYSTEMDRIVE}\${Env:ComputerName}\REGISTRY\${Env:ComputerName}-SAM
#Dump available User registries separately.  Some may error out. Like the blank top line.
#First generate list of potential user registries.
reg query HKU > ${SYSTEMDRIVE}\${Env:ComputerName}\REGISTRY\HKU-list.txt
#Then cleanup the list.
(Get-Content ${SYSTEMDRIVE}\${Env:ComputerName}\REGISTRY\HKU-list.txt) -replace "HKEY_USERS\\","" >> ${SYSTEMDRIVE}\${Env:ComputerName}\REGISTRY\HKU-list.txt
#Now iterate through the list and save each key.
$RegistryUsers = Get-Content ${SYSTEMDRIVE}\${Env:ComputerName}\REGISTRY\HKU-list.txt
ForEach ($RegistryUser in $RegistryUsers)
{
reg save HKU\$RegistryUser ${SYSTEMDRIVE}\${Env:ComputerName}\REGISTRY\${Env:ComputerName}-$RegistryUser-NThive}

#########   WEB ARTIFACTS    #########
#Build list of user folders
Get-ChildItem -Directory c:\Users -Name >> ${SYSTEMDRIVE}\${Env:ComputerName}\INTERNET\${Env:ComputerName}-UserFolders.txt

#Iterate User profile folders and then grab each profile's WebCache folder.  
#At end of script b/c command shuts down certain services and processes.  Best if machine is restarted once the entire collection is finished. 
#May only need the taskkill for taskhost.exe command on certain systems.
net stop COMSysApp
taskkill /F /IM dllhost.exe
taskkill /F /IM taskhost.exe
taskkill /F /IM taskhostex.exe
Get-ChildItem -Directory c:\Users -Name >> ${SYSTEMDRIVE}\${Env:ComputerName}\INTERNET\${Env:ComputerName}-UserFolders.txt
$UserFolders = Get-Content  ${SYSTEMDRIVE}\${Env:ComputerName}\INTERNET\${Env:ComputerName}-UserFolders.txt
ForEach ($UserFolder in $UserFolders)
{
robocopy C:\Users\$UserFolder\AppData\Local\Microsoft\Windows\WebCache ${SYSTEMDRIVE}\${Env:ComputerName}\INTERNET\${Env:ComputerName}-$UserFolder\WebCache /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:${SYSTEMDRIVE}\${Env:ComputerName}\INTERNET\${Env:ComputerName}-$UserFolder-WebCacheV01GrabLog.txt}
net start ComSysApp

#Grab Firefox SQLITE Files, if available, from each user profile.
$UserFolders = Get-Content ${SYSTEMDRIVE}\${Env:ComputerName}\INTERNET\${Env:ComputerName}-UserFolders.txt
ForEach ($UserFolder in $UserFolders)
{
robocopy C:\Users\$UserFolder\AppData\Roaming\Mozilla\Firefox\Profiles ${SYSTEMDRIVE}\${Env:ComputerName}\INTERNET\${Env:ComputerName}-$UserFolder\Firefox *.sqlite /S /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:${SYSTEMDRIVE}\${Env:ComputerName}\INTERNET\${Env:ComputerName}-$UserFolder-FirefoxGrabLog.txt}
#Grab all Google Chrome data, if available, from each user profile.
$UserFolders = Get-Content ${SYSTEMDRIVE}\${Env:ComputerName}\INTERNET\${Env:ComputerName}-UserFolders.txt
ForEach ($UserFolder in $UserFolders)
{
robocopy "C:\Users\$UserFolder\AppData\Local\Google\Chrome\User Data" ${SYSTEMDRIVE}\${Env:ComputerName}\INTERNET\${Env:ComputerName}-$UserFolder\Chrome /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:${SYSTEMDRIVE}\${Env:ComputerName}\INTERNET\${Env:ComputerName}-$UserFolder-ChromeGrabLog.txt}

#Grab Jump Lists for each user found on the system. Automatic and pinned(custom).
$UserFolders = Get-Content ${SYSTEMDRIVE}\${Env:ComputerName}\INTERNET\${Env:ComputerName}-UserFolders.txt
ForEach ($UserFolder in $UserFolders)
{
robocopy "C:\Users\$UserFolder\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" "${SYSTEMDRIVE}\${Env:ComputerName}\JUMPLISTS\${Env:ComputerName}-$UserFolder\" /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:${SYSTEMDRIVE}\${Env:ComputerName}\JUMPLISTS\${Env:ComputerName}-$UserFolder-jumplists.txt
robocopy "C:\Users\$UserFolder\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations" "${SYSTEMDRIVE}\${Env:ComputerName}\JUMPLISTS\${Env:ComputerName}-$UserFolder\" /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:${SYSTEMDRIVE}\${Env:ComputerName}\JUMPLISTS\${Env:ComputerName}-$UserFolder-jumplists.txt} 

#CONTENTS OF PREFETCH FOLDER
Get-ChildItem C:\Windows\Prefetch | select-object Name, FullName, CreationTime, LastAccessTime, LastWriteTime, Mode | Export-Csv ${SYSTEMDRIVE}\${Env:ComputerName}\${Env:ComputerName}-PreFetchFolder.csv -NoTypeInformation
#Copy prefetch folder contents
robocopy c:\windows\prefetch ${SYSTEMDRIVE}\${Env:ComputerName}\prefetch_grab /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:${SYSTEMDRIVE}\${Env:ComputerName}\${Env:ComputerName}-PrefetchGrabLog.txt