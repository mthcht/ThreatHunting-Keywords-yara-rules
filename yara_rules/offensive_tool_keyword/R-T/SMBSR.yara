rule SMBSR
{
    meta:
        description = "Detection patterns for the tool 'SMBSR' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBSR"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Lookup for interesting stuff in SMB shares
        // Reference: https://github.com/oldboy21/SMBSR
        $string1 = /\ssmbsr\.db/ nocase ascii wide
        // Description: Lookup for interesting stuff in SMB shares
        // Reference: https://github.com/oldboy21/SMBSR
        $string2 = /\ssmbsr\.log/ nocase ascii wide
        // Description: Lookup for interesting stuff in SMB shares
        // Reference: https://github.com/oldboy21/SMBSR
        $string3 = /\s\-word\-list\-path\s.{0,1000}\s\-file\-extensions\s/ nocase ascii wide
        // Description: Lookup for interesting stuff in SMB shares
        // Reference: https://github.com/oldboy21/SMBSR
        $string4 = /\/smbsr\.db/ nocase ascii wide
        // Description: Lookup for interesting stuff in SMB shares
        // Reference: https://github.com/oldboy21/SMBSR
        $string5 = /\/SMBSR\.git/ nocase ascii wide
        // Description: Lookup for interesting stuff in SMB shares
        // Reference: https://github.com/oldboy21/SMBSR
        $string6 = /\/smbsr\.log/ nocase ascii wide
        // Description: Lookup for interesting stuff in SMB shares
        // Reference: https://github.com/oldboy21/SMBSR
        $string7 = /smbsr\.py/ nocase ascii wide

    condition:
        any of them
}
