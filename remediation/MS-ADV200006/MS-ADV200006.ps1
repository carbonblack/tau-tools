<#
.SYNOPSIS
    This detects and mitigates if systems are vulnerable to Microsoft Security Adivsory ADV200006 | Type 1 Font Parsing Remote Code Execution Vulnerability

.DESCRIPTION
    This script will identify if a machine prior to Windows 10 has the Adobe Type Manager Library enabled by querying the registry, and optionally set mitigating registry keys to disable the Adobe Type Manager Library.

.PARAMETER mitigate 
    The parameter mitigate is used to apply the recommenced mitigations.
    https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200006

.PARAMETER backout 
    The parameter backout is used to remove the recommenced mitigations.
    https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200006

.EXAMPLE
    The example below mitigates the system if vulnerable to Microsoft Security Advisory ADV200006, Requires running as Admin
    PS C:\> ./ADV200006.ps1 -mitigate

.EXAMPLE
    The example below checks if the system is vulnerable to Microsoft Security Advisory ADV200006
    PS C:\> ./ADV200006.ps1

.NOTES
    Author: Casey Parman
    Last Edit: 2020-03-11
    Version 1.0 - initial release
    Copyright VMware 2020
#>
param
(
    [switch]$mitigate,
    [switch]$backout
)



If ([environment]::OSVersion.Version.Major -eq 10) 
{
    Write-Host -ForegroundColor Green "----------------------------------------------------------------------------------"
    Write-Host -ForegroundColor Green "-- Microsoft does not recommend mitigations for Windows 10 systems              --"
    Write-Host -ForegroundColor Green "-- https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200006 --"
    Write-Host -ForegroundColor Green "----------------------------------------------------------------------------------"
    Exit 0
}

$KB = "KB NOT YET RELEASED"
write-host -ForegroundColor DarkRed ">>> $KB"

if ((get-wmiobject -class win32_quickfixengineering | FL HotFixID) -contains $KB ) { $patchstate = $true; } else { $patchstate = $false; }

If ( $backout ) {
    Write-Host -ForegroundColor Red "---------------------------------------"
    try {
        if ( (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name DisableATMFD) -eq 1 ) {
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name DisableATMFD
            Write-Host -ForegroundColor Red "-- Mitigation removed                --"
        } Else {
            Write-Host -ForegroundColor Red "-- No mitigation to remove, skipping --"
        }
    } catch {
        Write-Host -ForegroundColor Red "-- No mitigation to remove, skipping --"
    }
    Write-Host -ForegroundColor Red "---------------------------------------"
}

If ( $patchstate -eq $true ) {
    Write-Host -ForegroundColor Green "------------------"
    Write-Host -ForegroundColor Green "--Not Vulnerable--"
    Write-Host -ForegroundColor Green "------------------"
    Exit 0
}

If ( $patchstate -eq $false ) {
    Write-Host -ForegroundColor Red "-------------------"
    Write-Host -ForegroundColor Red "-- Patch Missing --"
    Write-Host -ForegroundColor Red "-------------------"
    try {
        if ( (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name DisableATMFD) -eq 1 ) {
            Write-Host -ForegroundColor Green "----------------------"
            Write-Host -ForegroundColor Green "-- System Mitigated --"
            Write-Host -ForegroundColor Green "----------------------"
            Exit 0
        } Else {
            throw "wrong registry value"
        }
    } catch {
        If ($mitigate) 
        {
            If (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
            {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" DisableATMFD -Type DWORD -Value 1 -Force
                Write-Host -ForegroundColor Green "----------------------"
                Write-Host -ForegroundColor Green "-- System Mitigated --"
                Write-Host -ForegroundColor Green "----------------------"   
            } Else {
                Write-Host -ForegroundColor Red "Run in elevated prompt"
            }
        } Else {
            Write-Host -ForegroundColor Red "--------------------------------------"
            Write-Host -ForegroundColor Red "-----------Vulnerable-----------------"
            Write-Host -ForegroundColor Red "--------------------------------------"
            Write-Host -ForegroundColor Red "-- mitigate with -mitigate argument --"
            Write-Host -ForegroundColor Red "--------------------------------------"
        }
    }
}
