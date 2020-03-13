# EternalDarkness CVE-2020-0796 Mitigation

## References
https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0796
https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200005

## Summary
Specifically this vulnerability would allow an unauthenticated attacker to exploit this vulnerability by sending a specially crafted packet
to a vulnerable SMBv3 Server.  Similarly if an attacker could convince or trick a user into connecting to a malicious SMBv3 Server, 
then the user’s SMB3 client could also be exploited.  Regardless if the target or host is successfully exploited, this would grant the 
attacker the ability to execute arbitrary code.

In addition to disabling SMB compression on an impacted server, Microsoft advised blocking any inbound or outbound traffic on TCP port 445 at 
the perimeter firewall. Additionally the Computer Emergency Response Team Coordination Center (CERT/CC) advised that organizations should verify 
that SMB connections from the internet are not allowed to connect inbound to an enterprise LAN.

While these workarounds will prevent external exploitation of SMBv3 Server, it is important to note that SMBv3 Client will remain vulnerable until 
a patch is available and applied.  Microsoft has confirmed that there is no evidence to suggest that the vulnerability has been exploited as of yet, 
no mitigating factors have been identified, and that no update to fix it is currently available.


## Description

This detects and mitigates if systems are vulnerable to CVE-2020-0796 EternalDarkness

This script will check OS version and if any shares are enabled.  If OS version matches and shares are enabled 
it will check HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameter\DisableCompression to determine if the host system is vulnerable.
If the host system is vulnerable and -mitigate is used it will set DisableCompression to 1

## Instructions

Usage:



Checking if device is vulnerable to EnternalDarkness
```Powershell
EternalDarkness.ps1
```

Mitigating systems that are vulnerable to EternalDarkness
```Powershell
EternalDarkness.ps1 -mitigate
```

## Example

```Powershell
PS C:\> .\EternalDarkness.ps1
-----------------
--Patch Missing--
-----------------
--------------
--Vulnerable--
--------------------------------
mitigate with -mitigate argument
--------------------------------
PS C:\> .\EternalDarkness -mitigate
-----------------
--Patch Missing--
-----------------
Run in elevated prompt
```
Elevated Prompt:
```Powershell
PS C:\> .\EternalDarkness.ps1 -mitigate
-----------------
--Patch Missing--
-----------------
--------------------
--System Mitigated--
--------------------
PS C:\> .\EternalDarkness.ps1
-----------------
--Patch Missing--
-----------------
------------------
--Not Vulnerable--
------------------
```


## Live Response Wrapper

The EternalDarkness-LR.py script is a wrapper for executing the EternalDarkness.ps1 script remotely via the VMware Carbon Black Cloud API.

Usage:
```PowerShell
EternalDarkness-LR.py [-h] [-m MACHINENAME] [-c] [-p] [-o ORGPROFILE]

optional arguments:
  -h, --help            show this help message and exit
  -m MACHINENAME, --machinename MACHINENAME
                        machinename to run host forensics recon on
  -c, --check           Check the system for the vulnerable SMBv3
                        Configuration
  -p, --patch           Mitigate the vulnerable system SMBv3 configuration
                        by disabling compression
  -o ORGPROFILE, --orgprofile ORGPROFILE
                        Select your cbapi credential profile
```

## Example

Checking for vulnerable SMBv3 configuration:
```PowerShell
$ python3 EternalDarkness-LR.py -m <hostname> -c -o <cbapi profile>
```

Mitigating vulnerable SMBv3 configuration:
```PowerShell
$ python3 EternalDarkness-LR.py -m <hostname> -p -o <cbapi profile>
```

This script is compatible with the full VMware Carbon Black Cloud API and requires the python cbapi