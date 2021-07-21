# HiveNightmare CVE-2021-36934 Mitigation
​
## References
[Microsoft Bulletin](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934)
[CERT Coordination Center Bullentin](https://www.kb.cert.org/vuls/id/506989)
​
## Summary
On July 20, 2021, Microsoft released a bulletin regarding CVE-2021-36934. This specific vulnerability affects **Windows 10 version 1809** and newer operating systems, and provides read and execute **(“RX”)** permissions to any account in the **“BUILTIN\Users”** group of the **%windir%\system32\config** directory. The BUILTIN\Users group includes any accounts in the Authenticated Users group (anyone logged into the system) and the Domain Users group (which is a global group that, by default, includes all user accounts in a domain). 
​
This allows any valid user account to access a typically restricted directory, which contains, among other files, copies of the Security Accounts Manager (SAM) registry hive if the system was currently leveraging the Volume Shadow Copy Service (VSS). The SAM, or other files, could then be leveraged to obtain user account password hashes or perform numerous other techniques. 
​
​
## Description
This will restrict access to the **%windir%\system32\config** directory by enabling the inheritance level of files in the directory, as well as removing previously created volume shadow copies.  As new shadow copies are created they will have the appropriate permissions to not allow privilege users access to those files.
​
​
## Examples
### Check System
```
.\HiveNightmare.ps1
---------------------
--System Vulnerable--
---------------------
```

### Mitigate System
```
.\HiveNightmare.ps1 -mitigate
---------------------
--System Vulnerable--
---------------------
Updating folder permissions for C:\WINDOWS\system32\config
processed file: C:\WINDOWS\system32\config\BBI
processed file: C:\WINDOWS\system32\config\BBI.LOG1
processed file: C:\WINDOWS\system32\config\BBI.LOG2
processed file: C:\WINDOWS\system32\config\bbimigrate
processed file: C:\WINDOWS\system32\config\BBI{53b39ea0-18c4-11ea-a811-000d3aa4692b}.TM.blf
processed file: C:\WINDOWS\system32\config\BBI{53b39ea0-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms
processed file: C:\WINDOWS\system32\config\BBI{53b39ea0-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000002.regtrans-ms
processed file: C:\WINDOWS\system32\config\BCD-Template
processed file: C:\WINDOWS\system32\config\BCD-Template.LOG
processed file: C:\WINDOWS\system32\config\BCD-Template.LOG1
processed file: C:\WINDOWS\system32\config\BCD-Template.LOG2
processed file: C:\WINDOWS\system32\config\COMPONENTS
processed file: C:\WINDOWS\system32\config\COMPONENTS.LOG1
processed file: C:\WINDOWS\system32\config\COMPONENTS.LOG2
processed file: C:\WINDOWS\system32\config\COMPONENTS{53b39e63-18c4-11ea-a811-000d3aa4692b}.TM.blf
processed file: C:\WINDOWS\system32\config\COMPONENTS{53b39e63-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms
processed file: C:\WINDOWS\system32\config\COMPONENTS{53b39e63-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000002.regtrans-ms
processed file: C:\WINDOWS\system32\config\DEFAULT
processed file: C:\WINDOWS\system32\config\DEFAULT.LOG1
processed file: C:\WINDOWS\system32\config\DEFAULT.LOG2
processed file: C:\WINDOWS\system32\config\DEFAULT{53b39e7c-18c4-11ea-a811-000d3aa4692b}.TM.blf
processed file: C:\WINDOWS\system32\config\DEFAULT{53b39e7c-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms
processed file: C:\WINDOWS\system32\config\DEFAULT{53b39e7c-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000002.regtrans-ms
processed file: C:\WINDOWS\system32\config\DRIVERS
processed file: C:\WINDOWS\system32\config\DRIVERS.LOG1
processed file: C:\WINDOWS\system32\config\DRIVERS.LOG2
processed file: C:\WINDOWS\system32\config\DRIVERS{53b39e70-18c4-11ea-a811-000d3aa4692b}.TM.blf
processed file: C:\WINDOWS\system32\config\DRIVERS{53b39e70-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms
processed file: C:\WINDOWS\system32\config\DRIVERS{53b39e70-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000002.regtrans-ms
processed file: C:\WINDOWS\system32\config\ELAM
processed file: C:\WINDOWS\system32\config\ELAM.LOG1
processed file: C:\WINDOWS\system32\config\ELAM.LOG2
processed file: C:\WINDOWS\system32\config\ELAM{53b39eac-18c4-11ea-a811-000d3aa4692b}.TM.blf
processed file: C:\WINDOWS\system32\config\ELAM{53b39eac-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms
processed file: C:\WINDOWS\system32\config\ELAM{53b39eac-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000002.regtrans-ms
processed file: C:\WINDOWS\system32\config\Journal
processed file: C:\WINDOWS\system32\config\RegBack
processed file: C:\WINDOWS\system32\config\SAM
processed file: C:\WINDOWS\system32\config\SAM.LOG1
processed file: C:\WINDOWS\system32\config\SAM.LOG2
processed file: C:\WINDOWS\system32\config\SAM{53b39e57-18c4-11ea-a811-000d3aa4692b}.TM.blf
processed file: C:\WINDOWS\system32\config\SAM{53b39e57-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms
processed file: C:\WINDOWS\system32\config\SAM{53b39e57-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000002.regtrans-ms
processed file: C:\WINDOWS\system32\config\SECURITY
processed file: C:\WINDOWS\system32\config\SECURITY.LOG1
processed file: C:\WINDOWS\system32\config\SECURITY.LOG2
processed file: C:\WINDOWS\system32\config\SECURITY{53b39e4b-18c4-11ea-a811-000d3aa4692b}.TM.blf
processed file: C:\WINDOWS\system32\config\SECURITY{53b39e4b-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms
processed file: C:\WINDOWS\system32\config\SECURITY{53b39e4b-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000002.regtrans-ms
processed file: C:\WINDOWS\system32\config\SOFTWARE
processed file: C:\WINDOWS\system32\config\SOFTWARE.LOG1
processed file: C:\WINDOWS\system32\config\SOFTWARE.LOG2
processed file: C:\WINDOWS\system32\config\SOFTWARE{53b39e2f-18c4-11ea-a811-000d3aa4692b}.TM.blf
processed file: C:\WINDOWS\system32\config\SOFTWARE{53b39e2f-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms
processed file: C:\WINDOWS\system32\config\SOFTWARE{53b39e2f-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000002.regtrans-ms
processed file: C:\WINDOWS\system32\config\SYSTEM
processed file: C:\WINDOWS\system32\config\SYSTEM.LOG1
processed file: C:\WINDOWS\system32\config\SYSTEM.LOG2
processed file: C:\WINDOWS\system32\config\systemprofile
processed file: C:\WINDOWS\system32\config\SYSTEM{53b39e3e-18c4-11ea-a811-000d3aa4692b}.TM.blf
processed file: C:\WINDOWS\system32\config\SYSTEM{53b39e3e-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms
processed file: C:\WINDOWS\system32\config\SYSTEM{53b39e3e-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000002.regtrans-ms
processed file: C:\WINDOWS\system32\config\TxR
processed file: C:\WINDOWS\system32\config\userdiff
processed file: C:\WINDOWS\system32\config\userdiff.LOG1
processed file: C:\WINDOWS\system32\config\userdiff.LOG2
Successfully processed 66 files; Failed processing 0 files
Successfully Updated folder permissions for C:\WINDOWS\system32\config
Deleting Volume Shadow Copies of System Drive
--------------------
--System Mitigated--
--------------------
Warning: Running this mitigation script will remove all SystemDrive shadow copies.  This will prevent restoration - the backups are deleted.  It is recommended to run a comma
nd like this to create a fresh, properly permissioned shadow copy following mitigation: (gwmi -list win32_shadowcopy).Create("$env:systemdrive\",'ClientAccessible')
```
​
​
## Live Response Wrapper
​
The HiveNightmare-LR.py script is a wrapper for executing the HiveNightmare.ps1 script remotely via the VMware Carbon Black Cloud API.
**cbapi-python** is required installation instructions can be found here [cbapi-python-install](https://cbapi.readthedocs.io/en/latest/installation.html)
​
Usage:
```Python                     
usage: HiveNightmare-LR.py [-h] [--hostname HOSTNAME] [--check] [--mitigate] [--orgprofile ORGPROFILE]

optional arguments:
  -h, --help            show this help message and exit
  --hostname HOSTNAME   hostname to run host forensics recon on
  --check               Check the system for the vulnerable system32\config files
  --mitigate            Mitigate the vulnerable system's vulnerable system32\config files
  --orgprofile ORGPROFILE
                        Select your cbapi credential profile
```
​
## Example
### Check System
```
​python HiveNightmare-LR.py --hostname NightMare --check

[ * ] Establishing LiveResponse Session with Remote Host:
     - Hostname: NightMare
     - OS Version: Windows 10 x64
     - Sensor Version: 3.7.0.1253
     - AntiVirus Status: ['AV_ACTIVE', 'ONACCESS_SCAN_DISABLED', 'ONDEMAND_SCAN_DISABLED']
     - Internal IP Address: 172.16.40.10
     - External IP Address: 257.275.295.265

[ * ] Uploading HiveNightmare.ps1 to the remote host
[ * ] Checking the system for vulnerable system32\config files:

---------------------
--System Vulnerable--
---------------------

[ * ] Removing HiveNightmare.ps1
```
### Mitigate System

```
 python HiveNightmare-LR.py --hostname NightMare --mitigate

[ * ] Establishing LiveResponse Session with Remote Host:
     - Hostname: NightMare
     - OS Version: Windows 10 x64
     - Sensor Version: 3.7.0.1253
     - AntiVirus Status: ['AV_ACTIVE', 'ONACCESS_SCAN_DISABLED', 'ONDEMAND_SCAN_DISABLED']
     - Internal IP Address: 172.16.40.10
     - External IP Address: 257.275.295.265

[ * ] Uploading HiveNightmare.ps1 to the remote host
[ * ] Mitigating the vulnerable system32\config files:

---------------------
--System Vulnerable--
---------------------
Updating folder permissions for C:\WINDOWS\system32\config
processed file: C:\WINDOWS\system32\config\BBI
processed file: C:\WINDOWS\system32\config\BBI.LOG1
processed file: C:\WINDOWS\system32\config\BBI.LOG2
processed file: C:\WINDOWS\system32\config\bbimigrate
processed file: C:\WINDOWS\system32\config\BBI{53b39ea0-18c4-11ea-a811-000d3aa4692b}.TM.blf
processed file: C:\WINDOWS\system32\config\BBI{53b39ea0-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms
processed file: C:\WINDOWS\system32\config\BBI{53b39ea0-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000002.regtrans-ms
processed file: C:\WINDOWS\system32\config\BCD-Template
processed file: C:\WINDOWS\system32\config\BCD-Template.LOG
processed file: C:\WINDOWS\system32\config\BCD-Template.LOG1
processed file: C:\WINDOWS\system32\config\BCD-Template.LOG2
processed file: C:\WINDOWS\system32\config\COMPONENTS
processed file: C:\WINDOWS\system32\config\COMPONENTS.LOG1
processed file: C:\WINDOWS\system32\config\COMPONENTS.LOG2
processed file: C:\WINDOWS\system32\config\COMPONENTS{53b39e63-18c4-11ea-a811-000d3aa4692b}.TM.blf
processed file: C:\WINDOWS\system32\config\COMPONENTS{53b39e63-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms
processed file: C:\WINDOWS\system32\config\COMPONENTS{53b39e63-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000002.regtrans-ms
processed file: C:\WINDOWS\system32\config\DEFAULT
processed file: C:\WINDOWS\system32\config\DEFAULT.LOG1
processed file: C:\WINDOWS\system32\config\DEFAULT.LOG2
processed file: C:\WINDOWS\system32\config\DEFAULT{53b39e7c-18c4-11ea-a811-000d3aa4692b}.TM.blf
processed file: C:\WINDOWS\system32\config\DEFAULT{53b39e7c-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms
processed file: C:\WINDOWS\system32\config\DEFAULT{53b39e7c-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000002.regtrans-ms
processed file: C:\WINDOWS\system32\config\DRIVERS
processed file: C:\WINDOWS\system32\config\DRIVERS.LOG1
processed file: C:\WINDOWS\system32\config\DRIVERS.LOG2
processed file: C:\WINDOWS\system32\config\DRIVERS{53b39e70-18c4-11ea-a811-000d3aa4692b}.TM.blf
processed file: C:\WINDOWS\system32\config\DRIVERS{53b39e70-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms
processed file: C:\WINDOWS\system32\config\DRIVERS{53b39e70-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000002.regtrans-ms
processed file: C:\WINDOWS\system32\config\ELAM
processed file: C:\WINDOWS\system32\config\ELAM.LOG1
processed file: C:\WINDOWS\system32\config\ELAM.LOG2
processed file: C:\WINDOWS\system32\config\ELAM{53b39eac-18c4-11ea-a811-000d3aa4692b}.TM.blf
processed file: C:\WINDOWS\system32\config\ELAM{53b39eac-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms
processed file: C:\WINDOWS\system32\config\ELAM{53b39eac-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000002.regtrans-ms
processed file: C:\WINDOWS\system32\config\Journal
processed file: C:\WINDOWS\system32\config\RegBack
processed file: C:\WINDOWS\system32\config\SAM
processed file: C:\WINDOWS\system32\config\SAM.LOG1
processed file: C:\WINDOWS\system32\config\SAM.LOG2
processed file: C:\WINDOWS\system32\config\SAM{53b39e57-18c4-11ea-a811-000d3aa4692b}.TM.blf
processed file: C:\WINDOWS\system32\config\SAM{53b39e57-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms
processed file: C:\WINDOWS\system32\config\SAM{53b39e57-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000002.regtrans-ms
processed file: C:\WINDOWS\system32\config\SECURITY
processed file: C:\WINDOWS\system32\config\SECURITY.LOG1
processed file: C:\WINDOWS\system32\config\SECURITY.LOG2
processed file: C:\WINDOWS\system32\config\SECURITY{53b39e4b-18c4-11ea-a811-000d3aa4692b}.TM.blf
processed file: C:\WINDOWS\system32\config\SECURITY{53b39e4b-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms
processed file: C:\WINDOWS\system32\config\SECURITY{53b39e4b-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000002.regtrans-ms
processed file: C:\WINDOWS\system32\config\SOFTWARE
processed file: C:\WINDOWS\system32\config\SOFTWARE.LOG1
processed file: C:\WINDOWS\system32\config\SOFTWARE.LOG2
processed file: C:\WINDOWS\system32\config\SOFTWARE{53b39e2f-18c4-11ea-a811-000d3aa4692b}.TM.blf
processed file: C:\WINDOWS\system32\config\SOFTWARE{53b39e2f-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms
processed file: C:\WINDOWS\system32\config\SOFTWARE{53b39e2f-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000002.regtrans-ms
processed file: C:\WINDOWS\system32\config\SYSTEM
processed file: C:\WINDOWS\system32\config\SYSTEM.LOG1
processed file: C:\WINDOWS\system32\config\SYSTEM.LOG2
processed file: C:\WINDOWS\system32\config\systemprofile
processed file: C:\WINDOWS\system32\config\SYSTEM{53b39e3e-18c4-11ea-a811-000d3aa4692b}.TM.blf
processed file: C:\WINDOWS\system32\config\SYSTEM{53b39e3e-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms
processed file: C:\WINDOWS\system32\config\SYSTEM{53b39e3e-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000002.regtrans-ms
processed file: C:\WINDOWS\system32\config\TxR
processed file: C:\WINDOWS\system32\config\userdiff
processed file: C:\WINDOWS\system32\config\userdiff.LOG1
processed file: C:\WINDOWS\system32\config\userdiff.LOG2
Successfully processed 66 files; Failed processing 0 files
Successfully Updated folder permissions for C:\WINDOWS\system32\config
Deleting Volume Shadow Copies of System Drive
--------------------
--System Mitigated--
--------------------
Warning: Running this mitigation script will remove all SystemDrive shadow copies.  This will prevent restoration - the backups are deleted.  It is recommended to run a command like this to create a fresh, properly permissioned shadow copy following mitigation: (gwmi -list win32_shadowcopy).Create("$env:systemdrive\",'ClientAccessible')

[ * ] Removing HiveNightmare.ps1
```


​
This script is compatible with the full VMware Carbon Black Cloud API and requires the python cbapi