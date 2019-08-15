rule Powershell_reflective_injector_generic : TAU PowerShell b64MZ
{
     meta:
          author = "Carbon Black TAU" //jmyers
          date = "2019-Jun-21"
          description = "Designed to catch PowerShell script to reflectively inject embedded b64 MZ"
          link = ""
          rule_version = 1
          yara_version = "3.10.0"
          Confidence = "Prod"
          Priority = "Medium"
          TLP = "White"
          exemplar_hashes = "aabf130306337094e09e4b2f1845310cece8f81f50c4f10bfc43bf9cccb0923d,01f34e9ab8835626f0ae554cb89b8d772d4aa3dfaf392e05d906e0f4f7123369"
     strings:
          $s1 = "[CmdletBinding()]"
          $s2 = "$Win32Types = New-Object System.Object"
          $s3 = "TVqQAA"
          $s4 = "Invoke-Command"
          $s5 = "FromBase64String"
          $s6 = "Get-Win32Functions"
          $s7 = "Get-VirtualProtectValue"
     condition:
          all of them

}