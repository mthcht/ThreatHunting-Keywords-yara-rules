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
        $string2 = /\\SharpLDAP\\/ nocase ascii wide
        // Description: tool written in C# that aims to do enumeration via LDAP queries
        // Reference: https://github.com/mertdas/SharpLDAP
        $string3 = /01d38f94612e1b04e52b08c8ab75d8c614a5e9a716b01754ef4884a06e9669c3/ nocase ascii wide
        // Description: tool written in C# that aims to do enumeration via LDAP queries
        // Reference: https://github.com/mertdas/SharpLDAP
        $string4 = /5afab0c6f13f93b77c833816fd067007f9a0770ff0ce5096b55635fa3d9b96b4/ nocase ascii wide
        // Description: tool written in C# that aims to do enumeration via LDAP queries
        // Reference: https://github.com/mertdas/SharpLDAP
        $string5 = /90F6244A\-5EEE\-4A7A\-8C75\-FA6A52DF34D3/ nocase ascii wide
        // Description: tool written in C# that aims to do enumeration via LDAP queries
        // Reference: https://github.com/mertdas/SharpLDAP
        $string6 = /mertdas\/SharpLDAP/ nocase ascii wide
        // Description: tool written in C# that aims to do enumeration via LDAP queries
        // Reference: https://github.com/mertdas/SharpLDAP
        $string7 = /SharpLDAP\.csproj/ nocase ascii wide
        // Description: tool written in C# that aims to do enumeration via LDAP queries
        // Reference: https://github.com/mertdas/SharpLDAP
        $string8 = /SharpLDAP\.exe/ nocase ascii wide
        // Description: tool written in C# that aims to do enumeration via LDAP queries
        // Reference: https://github.com/mertdas/SharpLDAP
        $string9 = /SharpLDAP\.sln/ nocase ascii wide
        // Description: tool written in C# that aims to do enumeration via LDAP queries
        // Reference: https://github.com/mertdas/SharpLDAP
        $string10 = /SharpLDAP\-main/ nocase ascii wide

    condition:
        any of them
}
