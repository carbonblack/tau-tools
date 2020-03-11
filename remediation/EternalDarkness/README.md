# EternalDarkness Mitigation

## Description

This detects and mitigates if systems are vulnerable to CVE-2020-0796 EternalDarkness

This Module will check OS version and if any shares are enabled.  If OS version matches and shares are enabled 
it will check HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameter\DisableCompression to determine if the host system is vulnerable.
If the host system is vulnerable and -mitigate is used it will set DisableCompression to 1

## Instructions

This Script is created as a module called EternalDarkness

Usage:

Importing Module 
```Powershell
 Import-Module .\EternalDarkness.ps1
```

Checking if device is vulnerable to EnternalDarkness
```Powershell
EternalDarkness
```

Mitigating systems that are vulnerable to EternalDarkness
```Powershell
EternalDarkness -mitigate
```

## Example

```Powershell
PS C:\> Import-Module .\EternalDarkness.ps1
PS  C:\> EternalDarkness
OS Vulnerable with shares enabled
Device Vulnerable, to mitigate use the -mitigate argument
PS C:\> EternalDarkness -mitigate
OS Vulnerable with shares enabled
System Mitigated
PS C:\> EternalDarkness
OS Vulnerable with shares enabled
Compression Disabled Device Not Vulnerable

```