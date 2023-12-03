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
        $string1 = /.{0,1000}\/SharpLDAP\.git.{0,1000}/ nocase ascii wide
        // Description: tool written in C# that aims to do enumeration via LDAP queries
        // Reference: https://github.com/mertdas/SharpLDAP
        $string2 = /.{0,1000}90F6244A\-5EEE\-4A7A\-8C75\-FA6A52DF34D3.{0,1000}/ nocase ascii wide
        // Description: tool written in C# that aims to do enumeration via LDAP queries
        // Reference: https://github.com/mertdas/SharpLDAP
        $string3 = /.{0,1000}mertdas\/SharpLDAP.{0,1000}/ nocase ascii wide
        // Description: tool written in C# that aims to do enumeration via LDAP queries
        // Reference: https://github.com/mertdas/SharpLDAP
        $string4 = /.{0,1000}SharpLDAP\.csproj.{0,1000}/ nocase ascii wide
        // Description: tool written in C# that aims to do enumeration via LDAP queries
        // Reference: https://github.com/mertdas/SharpLDAP
        $string5 = /.{0,1000}SharpLDAP\.exe.{0,1000}/ nocase ascii wide
        // Description: tool written in C# that aims to do enumeration via LDAP queries
        // Reference: https://github.com/mertdas/SharpLDAP
        $string6 = /.{0,1000}SharpLDAP\.sln.{0,1000}/ nocase ascii wide
        // Description: tool written in C# that aims to do enumeration via LDAP queries
        // Reference: https://github.com/mertdas/SharpLDAP
        $string7 = /.{0,1000}SharpLDAP\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
