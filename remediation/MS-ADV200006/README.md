# Microsoft ADV200006 | Type 1 Font Parsing Remote Code Execution Vulnerability

## References
[https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200006](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200006)

## Recommendation

CB Recommends following Microsoft's mitigations to disable ATMFT on Windows 8.1
and below using either the rename or registry method provided by Microsoft.

## Summary

Microsoft published [Security Advisory
ADV200006](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200006)
on 3/24/2020 describing a zero-day remote-code execution vulnerability using the
Adobe Type Manager Library.  Microsoft described "limited targeted Windows 7
based attacks."

The Adobe library is a native implementation of Adobe Type Manager within Windows, added in Windows 2000/XP. <sup>[1](#footnote1)</sup>

From the Microsoft Security advisory:

> "Two remote code execution vulnerabilities exist in Microsoft Windows when the
> Windows Adobe Type Manager Library improperly handles a specially-crafted
> multi-master font - Adobe Type 1 PostScript format. There are multiple ways an
> attacker could exploit the vulnerability, such as convincing a user to open a
> specially crafted document or viewing it in the Windows Preview pane."

> "Please Note: The threat is low for those systems running Windows 10 due to
> mitigations that were put in place with the first version released in 2015."

Microsoft reported "...limited targeted Windows 7 based attacks.." and "...is
not aware of any attacks against the Windows 10 platform."

Microsoft considers the threat to be low for Windows 10 systems due to mitigations added in 2015:

> The possibility of remote code execution is negligible and elevation of
> privilege is not possible. We do not recommend that IT administrators running
> Windows 10 implement the workarounds described below."

## Detections

Reliable signatures specific to this threat are not yet available. Some
customers have considered queries related to `modload:atmfd.dll`, however this
DLL is loaded by the `ntoskrnl.exe` on boot, and the exclusions required to
prevent false positives from these queries may also cause false negatives. Other
VMWare Carbon Black Advanced Threats and other signatures are intended to
broadly cover the attack process, in order to stop an attack at multiple points
in the attackers kill chain. In this case, Carbon Black recommends close
monitoring of post-exploitation signatures for any Windows systems before
Windows 10.

## Mitigations

Microsoft provided three recommended mitigations, with specifics available at the Microsoft
Security Advisory
[ADV200006](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200006):


* Works on all systems but won't mitigate the issue if you open a document with the vulnerable font class
  * Disable the Preview Pane and Details Pane in Windows Explorer
  * Disable the WebClient service

* Only works on older (before Windows 10) but completely mitigates the issue
  though can introduce usability issues in rare cases
  * Rename `ATMFD.DLL`

> "Please note: ATMFD.DLL is not present in Windows 10 installations starting
> with Windows 10, version 1709. Newer versions do not have this DLL."

Microsoft does not recommend these mitigations on Windows 10 systems _currently supported by Microsoft_.

CB Recommends following Microsoft's mitigations to disable ATMFT on Windows 8.1
and below using either the rename or registry method provided by Microsoft.

### Mitigation Impact

From Microsoft

> "Applications that rely on embedded font technology will not display
> properly. Disabling ATMFD.DLL could cause certain applications to stop working
> properly if they use OpenType fonts. Microsoft Windows does not release any
> OpenType fonts natively. However, third-party applications could install them
> and they could be affected by this change."


### Identification and Mitigation of affected systems

VMWare Carbon Black TAU has published a PowerShell script to detect and mitigate
this vulnerability in our public
‘[tau-tools](https://github.com/carbonblack/tau-tools)’ GitHub repository:
[ADV200006](https://github.com/carbonblack/tau-tools/tree/master/remediation/MS-ADV200006). This
script will identify if a machine has active SMB shares, is running an OS
version impacted by this vulnerability, and check to see if the disabled
compression mitigating keys are set and optionally set mitigating keys. It can
be leveraged with any endpoint configuration management tools that support
PowerShell along with LiveResponse.

## Description

This detects and mitigates if systems are vulnerable to ADV200006: Type 1 Font Parsing Remote Code Execution Vulnerability

This script will identify if a machine prior to Windows 10 has the Adobe Type
Manager Library enabled by querying the registry, and optionally set mitigating
registry keys to disable the Adobe Type Manager Library.

If `[environment]::OSVersion.Version.Major` is not 10, then it will check if
`HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\DisableATMFD` is set
to 1, to see if the system has been mitigated. If the host system is vulnerable
and -mitigate is used it will set DisableATMFD to 1.

## Instructions

Usage:

Checking if device is vulnerable to MS-ADV200006
```Powershell
MS-ADV200006.ps1
```

Mitigating systems that are vulnerable to MS-ADV200006
```Powershell
MS-ADV200006.ps1 -mitigate
```

## Example

```Powershell
PS C:\> .\MS-ADV200006.ps1
>>> KB NOT YET RELEASED
-------------------
-- Patch Missing --
-------------------
--------------------------------------
-----------Vulnerable-----------------
--------------------------------------
-- mitigate with -mitigate argument --
--------------------------------------

PS C:\> .\MS-ADV200006.ps1 -mitigate
>>> KB NOT YET RELEASED
-------------------
-- Patch Missing --
-------------------
----------------------
-- System Mitigated --
----------------------

PS C:\> .\MS-ADV200006.ps1
>>> KB NOT YET RELEASED
-------------------
-- Patch Missing --
-------------------
----------------------
-- System Mitigated --
----------------------

PS C:\> .\MS-ADV200006.ps1 -backout
>>> KB NOT YET RELEASED
---------------------------------------
-- Mitigation removed --
---------------------------------------
-------------------
-- Patch Missing --
-------------------
--------------------------------------
-----------Vulnerable-----------------
--------------------------------------
-- mitigate with -mitigate argument --
--------------------------------------

PS C:\> 
```


## Live Response Wrapper

The `MS-ADV200006.py` script is a wrapper for executing the `MS-ADV200006.ps1` script remotely via the VMware Carbon Black Cloud API.

Usage:
```PowerShell
MS-ADV200006.py [-h] [-m MACHINENAME] [-c] [-p] [-o ORGPROFILE]

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

Checking for ADV200006 vulnerability:
```PowerShell
$ python3 MS-ADV200006.py -m <hostname> -c -o <cbapi profile>
```

Mitigating ADV200006 vulnerability:
```PowerShell
$ python3 MS-ADV200006.py -m <hostname> -p -o <cbapi profile>
```

This script is compatible with the full VMware Carbon Black Cloud API and requires the python cbapi


<a name="footnote1">1</a>: https://twitter.com/rosyna/status/1242156545346916352
