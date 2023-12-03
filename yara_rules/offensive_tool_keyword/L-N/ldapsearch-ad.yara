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
        $string1 = /.{0,1000}\s\-\-server\s.{0,1000}\s\-\-type\spass\-pols.{0,1000}/ nocase ascii wide
        // Description: Python3 script to quickly get various information from a domain controller through his LDAP service.
        // Reference: https://github.com/yaap7/ldapsearch-ad
        $string2 = /.{0,1000}\s\-\-type\sasreproast.{0,1000}/ nocase ascii wide
        // Description: Python3 script to quickly get various information from a domain controller through his LDAP service.
        // Reference: https://github.com/yaap7/ldapsearch-ad
        $string3 = /.{0,1000}\s\-\-type\ssearch\-spn.{0,1000}/ nocase ascii wide
        // Description: Python3 script to quickly get various information from a domain controller through his LDAP service.
        // Reference: https://github.com/yaap7/ldapsearch-ad
        $string4 = /.{0,1000}\/ldapsearch\-ad\.git.{0,1000}/ nocase ascii wide
        // Description: Python3 script to quickly get various information from a domain controller through his LDAP service.
        // Reference: https://github.com/yaap7/ldapsearch-ad
        $string5 = /.{0,1000}ldapsearchad\.py.{0,1000}/ nocase ascii wide
        // Description: Python3 script to quickly get various information from a domain controller through his LDAP service.
        // Reference: https://github.com/yaap7/ldapsearch-ad
        $string6 = /.{0,1000}ldapsearch\-ad\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
