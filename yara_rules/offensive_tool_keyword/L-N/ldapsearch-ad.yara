rule ldapsearch_ad
{
    meta:
        description = "Detection patterns for the tool 'ldapsearch-ad' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ldapsearch-ad"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Python3 script to quickly get various information from a domain controller through his LDAP service.
        // Reference: https://github.com/yaap7/ldapsearch-ad
        $string1 = /\s\-\-server\s.{0,1000}\s\-\-type\spass\-pols/ nocase ascii wide
        // Description: Python3 script to quickly get various information from a domain controller through his LDAP service.
        // Reference: https://github.com/yaap7/ldapsearch-ad
        $string2 = /\s\-\-type\sasreproast/ nocase ascii wide
        // Description: Python3 script to quickly get various information from a domain controller through his LDAP service.
        // Reference: https://github.com/yaap7/ldapsearch-ad
        $string3 = /\s\-\-type\ssearch\-spn/ nocase ascii wide
        // Description: Python3 script to quickly get various information from a domain controller through his LDAP service.
        // Reference: https://github.com/yaap7/ldapsearch-ad
        $string4 = /\/ldapsearch\-ad\.git/ nocase ascii wide
        // Description: Python3 script to quickly get various information from a domain controller through his LDAP service.
        // Reference: https://github.com/yaap7/ldapsearch-ad
        $string5 = /ldapsearchad\.py/ nocase ascii wide
        // Description: Python3 script to quickly get various information from a domain controller through his LDAP service.
        // Reference: https://github.com/yaap7/ldapsearch-ad
        $string6 = /ldapsearch\-ad\.py/ nocase ascii wide

    condition:
        any of them
}
