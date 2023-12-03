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
        $string1 = /.{0,1000}\/ADSearch\.git.{0,1000}/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string2 = /.{0,1000}adsearch.{0,1000}\s\-\-domain\-admins.{0,1000}/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string3 = /.{0,1000}adsearch\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string4 = /.{0,1000}ADSearch\.sln.{0,1000}/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string5 = /.{0,1000}ADSearch\\ADSearch\.cs.{0,1000}/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string6 = /.{0,1000}adsearch\-master\.zip/ nocase ascii wide
        // Description: A tool to help query AD via the LDAP protocol
        // Reference: https://github.com/tomcarver16/ADSearch
        $string7 = /.{0,1000}tomcarver16\/ADSearch.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
