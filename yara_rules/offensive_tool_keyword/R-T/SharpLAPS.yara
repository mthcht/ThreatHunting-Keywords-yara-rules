rule SharpLAPS
{
    meta:
        description = "Detection patterns for the tool 'SharpLAPS' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpLAPS"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Retrieve LAPS password from LDAP
        // Reference: https://github.com/swisskyrepo/SharpLAPS
        $string1 = /SharpLAPS\./ nocase ascii wide
        // Description: Retrieve LAPS password from LDAP
        // Reference: https://github.com/swisskyrepo/SharpLAPS
        $string2 = /SharpLAPS\-main/ nocase ascii wide
        // Description: Retrieve LAPS password from LDAP
        // Reference: https://github.com/swisskyrepo/SharpLAPS
        $string3 = /swisskyrepo\/SharpLAPS/ nocase ascii wide

    condition:
        any of them
}
