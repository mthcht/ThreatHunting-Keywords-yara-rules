rule SharpLDAP
{
    meta:
        description = "Detection patterns for the tool 'SharpLDAP' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpLDAP"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: tool written in C# that aims to do enumeration via LDAP queries
        // Reference: https://github.com/mertdas/SharpLDAP
        $string1 = /\/SharpLDAP\.git/ nocase ascii wide
        // Description: tool written in C# that aims to do enumeration via LDAP queries
        // Reference: https://github.com/mertdas/SharpLDAP
        $string2 = /90F6244A\-5EEE\-4A7A\-8C75\-FA6A52DF34D3/ nocase ascii wide
        // Description: tool written in C# that aims to do enumeration via LDAP queries
        // Reference: https://github.com/mertdas/SharpLDAP
        $string3 = /mertdas\/SharpLDAP/ nocase ascii wide
        // Description: tool written in C# that aims to do enumeration via LDAP queries
        // Reference: https://github.com/mertdas/SharpLDAP
        $string4 = /SharpLDAP\.csproj/ nocase ascii wide
        // Description: tool written in C# that aims to do enumeration via LDAP queries
        // Reference: https://github.com/mertdas/SharpLDAP
        $string5 = /SharpLDAP\.exe/ nocase ascii wide
        // Description: tool written in C# that aims to do enumeration via LDAP queries
        // Reference: https://github.com/mertdas/SharpLDAP
        $string6 = /SharpLDAP\.sln/ nocase ascii wide
        // Description: tool written in C# that aims to do enumeration via LDAP queries
        // Reference: https://github.com/mertdas/SharpLDAP
        $string7 = /SharpLDAP\-main/ nocase ascii wide

    condition:
        any of them
}