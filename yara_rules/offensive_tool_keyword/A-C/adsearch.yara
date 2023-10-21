rule adsearch
{
    meta:
        description = "Detection patterns for the tool 'adsearch' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adsearch"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string1 = /\/ADSearch\.git/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string2 = /adsearch.*\s\-\-domain\-admins/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string3 = /adsearch\.exe/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string4 = /ADSearch\.sln/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string5 = /ADSearch\\ADSearch\.cs/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string6 = /adsearch\-master\.zip/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string7 = /tomcarver16\/ADSearch/ nocase ascii wide

    condition:
        any of them
}