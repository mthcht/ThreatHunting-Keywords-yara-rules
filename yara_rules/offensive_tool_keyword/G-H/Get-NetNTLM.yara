rule Get_NetNTLM
{
    meta:
        description = "Detection patterns for the tool 'Get-NetNTLM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Get-NetNTLM"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Powershell module to get the NetNTLMv2 hash of the current user
        // Reference: https://github.com/elnerd/Get-NetNTLM
        $string1 = /\sGet\-NetNTLM\.ps1/ nocase ascii wide
        // Description: Powershell module to get the NetNTLMv2 hash of the current user
        // Reference: https://github.com/elnerd/Get-NetNTLM
        $string2 = /\/Get\-NetNTLM\.git/ nocase ascii wide
        // Description: Powershell module to get the NetNTLMv2 hash of the current user
        // Reference: https://github.com/elnerd/Get-NetNTLM
        $string3 = /\/Get\-NetNTLM\.ps1/ nocase ascii wide
        // Description: Powershell module to get the NetNTLMv2 hash of the current user
        // Reference: https://github.com/elnerd/Get-NetNTLM
        $string4 = /\\Get\-NetNTLM\.ps1/ nocase ascii wide
        // Description: Powershell module to get the NetNTLMv2 hash of the current user
        // Reference: https://github.com/elnerd/Get-NetNTLM
        $string5 = "cba7954a3a44198ede1f02ab8b4ce571d089b72b1dab61bd5cf004958a5e1172" nocase ascii wide
        // Description: Powershell module to get the NetNTLMv2 hash of the current user
        // Reference: https://github.com/elnerd/Get-NetNTLM
        $string6 = "elnerd/Get-NetNTLM" nocase ascii wide
        // Description: Powershell module to get the NetNTLMv2 hash of the current user
        // Reference: https://github.com/elnerd/Get-NetNTLM
        $string7 = "Get-NetNTLM-Hash " nocase ascii wide
        // Description: Powershell module to get the NetNTLMv2 hash of the current user
        // Reference: https://github.com/elnerd/Get-NetNTLM
        $string8 = /NTLM\sTlRMTVNTUAACAAAABgAGADgAAAAFAomiESIzRFVmd4gAAAAAAAAAAIAAgAA\+AAAABQLODgAAAA9TAE0AQgACAAYAUwBNAEIAAQAWAFMATQBCAC0AVABPAE8ATABLAEkAVAAEABIAcwBtAGIALgBsAG8AYwBhAGwAAwAoAHMAZQByAHYAZQByADIAMAAwADMALgBzAG0AYgAuAGwAbwBjAGEAbAAFABIAcwBtAGIALgBsAG8AYwBhAGwAAAAAAA\=\=/ nocase ascii wide

    condition:
        any of them
}
