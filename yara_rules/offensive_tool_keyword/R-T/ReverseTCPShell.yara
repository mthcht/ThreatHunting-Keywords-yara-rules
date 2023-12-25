rule ReverseTCPShell
{
    meta:
        description = "Detection patterns for the tool 'ReverseTCPShell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ReverseTCPShell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerShell ReverseTCP Shell - Framework
        // Reference: https://github.com/ZHacker13/ReverseTCPShell
        $string1 = /\/ReverseTCPShell/ nocase ascii wide
        // Description: PowerShell ReverseTCP Shell - Framework
        // Reference: https://github.com/ZHacker13/ReverseTCPShell
        $string2 = /function\sBase64_Obfuscation/ nocase ascii wide
        // Description: PowerShell ReverseTCP Shell - Framework
        // Reference: https://github.com/ZHacker13/ReverseTCPShell
        $string3 = /function\sBXOR_Obfuscation/ nocase ascii wide
        // Description: PowerShell ReverseTCP Shell - Framework
        // Reference: https://github.com/ZHacker13/ReverseTCPShell
        $string4 = /ReverseTCP\.ps1/ nocase ascii wide
        // Description: PowerShell ReverseTCP Shell - Framework
        // Reference: https://github.com/ZHacker13/ReverseTCPShell
        $string5 = /ReverseTCPShell\-main/ nocase ascii wide

    condition:
        any of them
}
