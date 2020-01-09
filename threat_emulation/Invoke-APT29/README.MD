## Invoke-APT29

    PowerShell Framework to allow for quick and easy simulation and cleanup of the known MITRE ATT&CK TIDs associated with APT29 (Cozy Bear)

#### About

Invoke-APT29 is an amalgamation of attack simulations specific to Cozy Bear that are included in the Atomic Red Team framework along with various custom-developed and augmented attack tests.

    TID -- Technique, Details
    ========================================
    T1015 -- Accessibility Features, APT29 used sticky-keys to obtain unauthenticated, privileged console access
    T1088 -- Bypass User Account Control, APT29 has bypassed UAC
    T1172 -- Domain Fronting, APT29 has used the meek domain fronting plugin for Tor to hide the destination of C2 traffic
    T1203 -- Exploitation for Client Execution, APT29 has used multiple software exploits for common client software, like Microsoft Word and Adobe Reader, to gain code execution
    T1070 -- Indicator Removal on Host, APT29 used SDelete to remove artifacts from victims
    T1188 -- Multi-hop Proxy, A backdoor used by APT29 created a Tor hidden service to forward traffic from the Tor client to local ports 3389 (RDP), 139 (Netbios), and 445 (SMB)
    T1075 -- Pass the Hash, APT29 used Kerberos ticket attacks for lateral movement
    T1086 -- PowerShell, APT29 has used encoded PowerShell scripts uploaded to CozyCar installations to download and install SeaDuke and evade defenses
    T1060 -- Registry Run Keys / Startup Folder, APT29 added Registry Run keys to establish persistence
    T1053 -- Scheduled Task, APT29 used named and hijacked scheduled tasks to establish persistence
    T1064 -- Scripting, APT29 has used encoded PowerShell scripts uploaded to CozyCar installations to download and install SeaDuke, as well as to evade defenses
    T1045 -- Software Packing, APT29 used UPX to pack files
    T1193 -- Spearphishing Attachment, APT29 has used spearphishing with an attachment to deliver files with exploits to initial victims
    T1192 -- Spearphishing Link, APT29 has used spearphishing with a link to trick victims into clicking on a link to a zip file containing malicious files
    T1204 -- User Execution, APT29 has used various forms of spearphishing attempting to get a user to open links or attachments
    T1047 -- Windows Management Instrumentation, APT29 used WMI to steal credentials and execute backdoors at a future time
    T1084 -- Windows Management Instrumentation Event Subscription, APT29 has used WMI event filters to establish persistence
    T1114 -- Email Collection from a local Outlook instance. APT29 collected and exfiltrated emails in the infamous DNC hack
    T1043 -- Commonly Used Port, APT29 has used Port Number 443 for C2
    T1027 -- Obfuscated Files or Information, APT29 uses PowerShell to use Base64 for obfuscation
    T1097 -- Pass the Ticket, APT29 used Kerberos ticket attacks for lateral movement
    T1085 -- Rundll32, APT29 has used rundll32.exe for execution
    T1023 -- Shortcut Modification, APT29 drops a Windows shortcut file for execution
    T1095 -- Standard Non-Application Layer Protocol, APT29 uses TCP for C2 communications

#### Usage

    Import the module
    PS C:\> Import-Module .\Invoke-APT29.ps1

    Show the help menu:
    PS C:\> Invoke-APT29 -help

    List all available simulation techniques - based on MITRE TID's
    PS C:\> Invoke-APT29 -listTechniques

    Search TIDs, attacks, tools, etc.
    PS C:\> Invoke-APT29 -search <search term>
    
    Establish a reverse shell - note to replace the PowerShell command here to point to your C2 instance
    PS C:\> Invoke-APT29 -shell
        Variants of this attack are -empire -meterpreter, -rundll32, and -mshta

    Show APT29-related information for a specific TID
    PS C:\> Invoke-APT29 -<MITRE TID> -about
        This will display MITRE ATT&CK information about the TID and simulation instructions
    
    List the available options for a given technique
    PS C:\> Invoke-APT29 -<MITRE TID> -listVariants
        This will display a list of variants associated with the given technique.
        When running the attack, use the listed number to call the associated attack technique.

    Simulate an attack
    PS C:\> Invoke-APT29 -<MITRE TID> -attack -variant <number>
        If the technique only has a single variant, just use the -attack flag
    PS C:\> Invoke-APT29 -<MITRE TID> -attack

    Cleanup after an attack simulation
    PS C:\> Invoke-APT29 -<MITRE TID> -cleanup
        Only necessary when the technique utilizes persistence or makes changes to the disk.
        Most techniques do not have an associated cleanup option

#### Thanks

[MITRE ATT&CK](https://attack.mitre.org/) for the detailed analysis and information on (APT29)[https://attack.mitre.org/groups/G0016/]

[Red Canary](https://redcanary.com/) for the following [Atomic Red Team](https://atomicredteam.io/) tests leveraged in this framework:

    T1015, T1088, T1070, T1060, T1053, T1056, T1193, T1047, T1084, T1114, T1027, T1097, T1085, T1023

