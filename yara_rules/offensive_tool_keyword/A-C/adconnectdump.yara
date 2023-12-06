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
        $string1 = /\/adconnectdump\.git/ nocase ascii wide
        // Description: Dump Azure AD Connect credentials for Azure AD and Active Directory
        // Reference: https://github.com/fox-it/adconnectdump
        $string2 = /adconnectdump\.py/ nocase ascii wide
        // Description: Dump Azure AD Connect credentials for Azure AD and Active Directory
        // Reference: https://github.com/fox-it/adconnectdump
        $string3 = /adconnectdump\-master/ nocase ascii wide
        // Description: Dump Azure AD Connect credentials for Azure AD and Active Directory
        // Reference: https://github.com/fox-it/adconnectdump
        $string4 = /ADSyncDecrypt\.exe/ nocase ascii wide
        // Description: Dump Azure AD Connect credentials for Azure AD and Active Directory
        // Reference: https://github.com/fox-it/adconnectdump
        $string5 = /ADSyncGather\.exe/ nocase ascii wide
        // Description: Dump Azure AD Connect credentials for Azure AD and Active Directory
        // Reference: https://github.com/fox-it/adconnectdump
        $string6 = /ADSyncQuery.{0,1000}ADSync\.mdf.{0,1000}\.txt/ nocase ascii wide
        // Description: Dump Azure AD Connect credentials for Azure AD and Active Directory
        // Reference: https://github.com/fox-it/adconnectdump
        $string7 = /decrypt\.py\s\.\\.{0,1000}\.txt\sutf\-16\-le/ nocase ascii wide
        // Description: Dump Azure AD Connect credentials for Azure AD and Active Directory
        // Reference: https://github.com/fox-it/adconnectdump
        $string8 = /fox\-it\/adconnectdump/ nocase ascii wide

    condition:
        any of them
}
