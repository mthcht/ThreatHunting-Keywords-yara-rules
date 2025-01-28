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
        $string1 = " ldeep_dump " nocase ascii wide
        // Description: In-depth ldap enumeration utility
        // Reference: https://github.com/franc-pentest/ldeep
        $string2 = "/ldeep/" nocase ascii wide
        // Description: In-depth ldap enumeration utility
        // Reference: https://github.com/franc-pentest/ldeep
        $string3 = /_dump_users\.lst/ nocase ascii wide
        // Description: In-depth ldap enumeration utility
        // Reference: https://github.com/franc-pentest/ldeep
        $string4 = /cache_activedirectory\.py/ nocase ascii wide
        // Description: In-depth ldap enumeration utility
        // Reference: https://github.com/franc-pentest/ldeep
        $string5 = "ldeep cache " nocase ascii wide
        // Description: In-depth ldap enumeration utility
        // Reference: https://github.com/franc-pentest/ldeep
        $string6 = "ldeep ldap -u " nocase ascii wide
        // Description: In-depth ldap enumeration utility
        // Reference: https://github.com/franc-pentest/ldeep
        $string7 = /ldeep.{0,1000}activedirectory\.py/ nocase ascii wide
        // Description: In-depth ldap enumeration utility
        // Reference: https://github.com/franc-pentest/ldeep
        $string8 = /ldeep.{0,1000}ldap_activedirectory\.py/ nocase ascii wide
        // Description: In-depth ldap enumeration utility
        // Reference: https://github.com/franc-pentest/ldeep
        $string9 = /ldeep_dump_users_enabled\.json/ nocase ascii wide
        // Description: In-depth ldap enumeration utility
        // Reference: https://github.com/franc-pentest/ldeep
        $string10 = /ldeep_dump_users_enabled\.lst/ nocase ascii wide

    condition:
        any of them
}
