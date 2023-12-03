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
        $string1 = /.{0,1000}\ssmbsr\.db.{0,1000}/ nocase ascii wide
        // Description: Lookup for interesting stuff in SMB shares
        // Reference: https://github.com/oldboy21/SMBSR
        $string2 = /.{0,1000}\ssmbsr\.log.{0,1000}/ nocase ascii wide
        // Description: Lookup for interesting stuff in SMB shares
        // Reference: https://github.com/oldboy21/SMBSR
        $string3 = /.{0,1000}\s\-word\-list\-path\s.{0,1000}\s\-file\-extensions\s.{0,1000}/ nocase ascii wide
        // Description: Lookup for interesting stuff in SMB shares
        // Reference: https://github.com/oldboy21/SMBSR
        $string4 = /.{0,1000}\/smbsr\.db.{0,1000}/ nocase ascii wide
        // Description: Lookup for interesting stuff in SMB shares
        // Reference: https://github.com/oldboy21/SMBSR
        $string5 = /.{0,1000}\/SMBSR\.git.{0,1000}/ nocase ascii wide
        // Description: Lookup for interesting stuff in SMB shares
        // Reference: https://github.com/oldboy21/SMBSR
        $string6 = /.{0,1000}\/smbsr\.log.{0,1000}/ nocase ascii wide
        // Description: Lookup for interesting stuff in SMB shares
        // Reference: https://github.com/oldboy21/SMBSR
        $string7 = /.{0,1000}smbsr\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
