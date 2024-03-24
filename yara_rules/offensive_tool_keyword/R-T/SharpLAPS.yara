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
        $string1 = /\[\+\]\sExtracting\sLAPS\spassword\sfrom\sLDAP/ nocase ascii wide
        // Description: Retrieve LAPS password from LDAP
        // Reference: https://github.com/swisskyrepo/SharpLAPS
        $string2 = /1E0986B4\-4BF3\-4CEA\-A885\-347B6D232D46/ nocase ascii wide
        // Description: Retrieve LAPS password from LDAP
        // Reference: https://github.com/swisskyrepo/SharpLAPS
        $string3 = /a0e17777243f0190053238f503971fc85321ffa8dc12b80bc50b93a2c0d3ea23/ nocase ascii wide
        // Description: Retrieve LAPS password from LDAP
        // Reference: https://github.com/swisskyrepo/SharpLAPS
        $string4 = /SharpLAPS\.csproj/ nocase ascii wide
        // Description: Retrieve LAPS password from LDAP
        // Reference: https://github.com/swisskyrepo/SharpLAPS
        $string5 = /SharpLAPS\.exe/ nocase ascii wide
        // Description: Retrieve LAPS password from LDAP
        // Reference: https://github.com/swisskyrepo/SharpLAPS
        $string6 = /SharpLAPS\.sln/ nocase ascii wide
        // Description: Retrieve LAPS password from LDAP
        // Reference: https://github.com/swisskyrepo/SharpLAPS
        $string7 = /SharpLAPS\-main/ nocase ascii wide
        // Description: Retrieve LAPS password from LDAP
        // Reference: https://github.com/swisskyrepo/SharpLAPS
        $string8 = /swisskyrepo\/SharpLAPS/ nocase ascii wide

    condition:
        any of them
}
