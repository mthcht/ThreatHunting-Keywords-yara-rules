rule ldeep
{
    meta:
        description = "Detection patterns for the tool 'ldeep' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ldeep"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: In-depth ldap enumeration utility
        // Reference: https://github.com/franc-pentest/ldeep
        $string1 = /.{0,1000}\sldeep_dump\s.{0,1000}/ nocase ascii wide
        // Description: In-depth ldap enumeration utility
        // Reference: https://github.com/franc-pentest/ldeep
        $string2 = /.{0,1000}\/ldeep\/.{0,1000}/ nocase ascii wide
        // Description: In-depth ldap enumeration utility
        // Reference: https://github.com/franc-pentest/ldeep
        $string3 = /.{0,1000}_dump_users\.lst.{0,1000}/ nocase ascii wide
        // Description: In-depth ldap enumeration utility
        // Reference: https://github.com/franc-pentest/ldeep
        $string4 = /.{0,1000}cache_activedirectory\.py.{0,1000}/ nocase ascii wide
        // Description: In-depth ldap enumeration utility
        // Reference: https://github.com/franc-pentest/ldeep
        $string5 = /.{0,1000}ldeep\scache\s.{0,1000}/ nocase ascii wide
        // Description: In-depth ldap enumeration utility
        // Reference: https://github.com/franc-pentest/ldeep
        $string6 = /.{0,1000}ldeep\sldap\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: In-depth ldap enumeration utility
        // Reference: https://github.com/franc-pentest/ldeep
        $string7 = /.{0,1000}ldeep.{0,1000}activedirectory\.py.{0,1000}/ nocase ascii wide
        // Description: In-depth ldap enumeration utility
        // Reference: https://github.com/franc-pentest/ldeep
        $string8 = /.{0,1000}ldeep.{0,1000}ldap_activedirectory\.py.{0,1000}/ nocase ascii wide
        // Description: In-depth ldap enumeration utility
        // Reference: https://github.com/franc-pentest/ldeep
        $string9 = /.{0,1000}ldeep_dump_users_enabled\.json/ nocase ascii wide
        // Description: In-depth ldap enumeration utility
        // Reference: https://github.com/franc-pentest/ldeep
        $string10 = /.{0,1000}ldeep_dump_users_enabled\.lst/ nocase ascii wide
        // Description: In-depth ldap enumeration utility
        // Reference: https://github.com/franc-pentest/ldeep
        $string11 = /ldeep\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
