rule adconnectdump
{
    meta:
        description = "Detection patterns for the tool 'adconnectdump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adconnectdump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dump Azure AD Connect credentials for Azure AD and Active Directory
        // Reference: https://github.com/fox-it/adconnectdump
        $string1 = /.{0,1000}\/adconnectdump\.git.{0,1000}/ nocase ascii wide
        // Description: Dump Azure AD Connect credentials for Azure AD and Active Directory
        // Reference: https://github.com/fox-it/adconnectdump
        $string2 = /.{0,1000}adconnectdump\.py.{0,1000}/ nocase ascii wide
        // Description: Dump Azure AD Connect credentials for Azure AD and Active Directory
        // Reference: https://github.com/fox-it/adconnectdump
        $string3 = /.{0,1000}adconnectdump\-master.{0,1000}/ nocase ascii wide
        // Description: Dump Azure AD Connect credentials for Azure AD and Active Directory
        // Reference: https://github.com/fox-it/adconnectdump
        $string4 = /.{0,1000}ADSyncDecrypt\.exe.{0,1000}/ nocase ascii wide
        // Description: Dump Azure AD Connect credentials for Azure AD and Active Directory
        // Reference: https://github.com/fox-it/adconnectdump
        $string5 = /.{0,1000}ADSyncGather\.exe.{0,1000}/ nocase ascii wide
        // Description: Dump Azure AD Connect credentials for Azure AD and Active Directory
        // Reference: https://github.com/fox-it/adconnectdump
        $string6 = /.{0,1000}ADSyncQuery.{0,1000}ADSync\.mdf.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: Dump Azure AD Connect credentials for Azure AD and Active Directory
        // Reference: https://github.com/fox-it/adconnectdump
        $string7 = /.{0,1000}decrypt\.py\s\.\\.{0,1000}\.txt\sutf\-16\-le.{0,1000}/ nocase ascii wide
        // Description: Dump Azure AD Connect credentials for Azure AD and Active Directory
        // Reference: https://github.com/fox-it/adconnectdump
        $string8 = /.{0,1000}fox\-it\/adconnectdump.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
