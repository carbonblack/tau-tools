rule Sodinokibi_ransomware_2019_Q3 : TAU ecrime ransomware
{
     meta:
          author = "Carbon Black TAU" //jmyers
          date = "2019-Jun-21"
          description = "Designed to catch Sodinokibi Ransomware Variants"
          link = ""
          rule_version = 1
          yara_version = "3.10.0"
          Confidence = "Prod"
          Priority = "Medium"
          TLP = "White"
          exemplar_hashes = "200d374121201b711c98b5bb778ab8ca46d334e06f2fc820a2ea7e70c251095e,32a72f3bc54b65651ec263c11e86738299d172043a9cdd146001780501c75078"
     strings:
          $s1 = "\\BaseNamedObjects" wide
          $s2 = "kernel32.dll" wide ascii
          $s3 = "kernelbase.dll" wide
          $s4 = "CreateThread"
          $s5 = "CloseHandle"
          $s6 = "kexpand"
          $s7 = {E8 58 3F 00 00}
          $s8 = {FF 35 24 E0 01 10}
          $s9 = {40 3D 00 01 00 00}
     condition:
          7 of ($s*)
}