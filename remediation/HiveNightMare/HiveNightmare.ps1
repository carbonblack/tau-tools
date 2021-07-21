<#
.SYNOPSIS
    This detects and mitigates if systems are vulnerable to CVE-2021-36934 HiveNightmare
    https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934
    
.DESCRIPTION
   This script will identify if a machine has unprivileged user access to system32\config files 
   and deletes volume shadow copies of system Drive
  

.PARAMETER mitigate 
    The parameter mitigate is used to apply the recommenced mitigation's.
    https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934
        1. Applies inheritance permissions to system32\config\
        2. Deletes all shadow copies of system drive

.EXAMPLE
    The example below mitigates the system if vulnerable to CVE-2021-36934 HiveNightmare, Requires running as Admin
    PS C:\> ./HiveNightmare -mitigate

.EXAMPLE
    The example below checks if the system is vulnerable to CVE-2021-36934 HiveNightmare
    PS C:\> ./HiveNightmare.ps1

.NOTES
    Author: Ed Myers & Casey Parman
    Last Edit: 2021-07-21
    Version 1.0 - initial release
    Copyright VMware 2021
#>
param
(
    [switch]$mitigate
)

#Mitigation
function Mitigation()
{
    $acl= Get-Acl $env:windir\system32\config\sam 
    if ($acl.Access.IdentityReference -ccontains "BUILTIN\Users")
    {
    write-host "Updating folder permissions for $env:windir\system32\config"
    & icacls $env:windir\system32\config\*.* /inheritance:e
    if ($? -eq "True") {
        write-host -ForegroundColor Green "Successfully Updated folder permissions for $env:windir\system32\config"
    }
    Else {
        write-host -ForegroundColor Red "Error Updating folder permissions for $env:windir\system32\config"
        return
    }
    } Else
    {
        Write-Host -ForegroundColor Green "-------------------------"
        Write-Host -ForegroundColor Green "--System Not Vulnerable--"
        Write-Host -ForegroundColor Green "-------------------------"
        return
    }
    #Get Volume information
    $Volume = (Get-WmiObject -Class Win32_Volume -Filter "DriveLetter = '$env:systemdrive'").deviceid
    ##Delete VSS
    Get-WmiObject Win32_Shadowcopy | ForEach-Object {
        if ($_.VolumeName -eq $Volume) 
            {
             write-host "Deleting Volume Shadow Copies of System Drive"
             $_.Delete();
            }
        }
        Write-Host -ForegroundColor Green "--------------------"
        Write-Host -ForegroundColor Green "--System Mitigated--"
        Write-Host -ForegroundColor Green "--------------------"
        $WarningMsg=@'
Warning: Running this mitigation script will remove all SystemDrive shadow copies.  This will prevent restoration - the backups are deleted.  It is recommended to run a command like this to create a fresh, properly permissioned shadow copy following mitigation: (gwmi -list win32_shadowcopy).Create("$env:systemdrive\",'ClientAccessible')
'@
        Write-Host -ForegroundColor Yellow $WarningMsg
}

If (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 
    {
        Write-Host -ForegroundColor Red "Run in elevated prompt"
        return
    }
 
$acl= Get-Acl $env:windir\system32\config\sam 
if ($acl.Access.IdentityReference -ccontains "BUILTIN\Users")
{
    Write-Host -ForegroundColor Red "---------------------"
    Write-Host -ForegroundColor Red "--System Vulnerable--"
    Write-Host -ForegroundColor Red "---------------------"
} Else
{
    Write-Host -ForegroundColor Green "-------------------------"
    Write-Host -ForegroundColor Green "--System Not Vulnerable--"
    Write-Host -ForegroundColor Green "-------------------------"
    return
}
    If ($mitigate) 
        {
            Mitigation
        }
                   