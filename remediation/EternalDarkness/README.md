# EternalDarkness Mitigation

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
--------------
--Vulnerable--
--------------------------------
mitigate with -mitigate argument
--------------------------------
PS C:\> .\EternalDarkness -mitigate
Run in elevated prompt
```
Elevated Prompt:
```Powershell
PS C:\> .\EternalDarkness.ps1 -mitigate
--------------------
--System Mitigated--
--------------------
PS C:\> .\EternalDarkness.ps1
------------------
--Not Vulnerable--
------------------
```
