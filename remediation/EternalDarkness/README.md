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


## Live Response Wrapper

The EternalDarkness-LR.py script is a wrapper for executing the EternalDarkness.ps1 script remotely via the VMware Carbon Black Cloud API.

Usage:
```Python
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
```Python
$ python3 EternalDarkness-LR.py -m <hostname> -c -o <cbapi profile>
```

Mitigating vulnerable SMBv3 configuration:
```Python
$ python3 EternalDarkness-LR.py -m <hostname> -p -o <cbapi profile>
```

This script is compatible with the full VMware Carbon Black Cloud API and requires the python cbapi