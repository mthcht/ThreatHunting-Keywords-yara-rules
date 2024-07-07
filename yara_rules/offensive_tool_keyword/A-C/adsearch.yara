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
        $string1 = /\s\-\-search\s\"\(\&\(objectCategory\=computer\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=524288\)\)/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string2 = /\s\-\-search\s\"\(\&\(objectCategory\=group\)\(cn\=.{0,1000}Admins/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string3 = /\s\-\-search\s\"\(\&\(objectCategory\=group\)\(cn\=MS\sSQL\sAdmins\)/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string4 = /\s\-\-search\s\"\(\&\(objectCategory\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=4194304\)\)/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string5 = /\/ADSearch\.git/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string6 = /adsearch.{0,1000}\s\-\-domain\-admins/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string7 = /adsearch\.exe/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string8 = /ADSearch\.sln/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string9 = /ADSearch\\ADSearch\.cs/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string10 = /adsearch\-master\.zip/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string11 = /tomcarver16\/ADSearch/ nocase ascii wide

    condition:
        any of them
}
