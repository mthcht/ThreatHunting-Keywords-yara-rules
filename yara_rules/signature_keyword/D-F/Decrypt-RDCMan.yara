rule Decrypt_RDCMan
{
    meta:
        description = "Detection patterns for the tool 'Decrypt-RDCMan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Decrypt-RDCMan"
        rule_category = "signature_keyword"

    strings:
        // Description: decrypts passwords stored in Remote Desktop Connection Manager (RDCMan) using DPAPI
        // Reference: https://github.com/vmamuaya/Powershell/blob/master/Decrypt-RDCMan.ps1
        $string1 = /HackTool\.DecryptRDCMan/ nocase ascii wide
        // Description: decrypts passwords stored in Remote Desktop Connection Manager (RDCMan) using DPAPI
        // Reference: https://github.com/vmamuaya/Powershell/blob/master/Decrypt-RDCMan.ps1
        $string2 = "HackTool:PowerShell/DecryptRDCMan" nocase ascii wide

    condition:
        any of them
}
