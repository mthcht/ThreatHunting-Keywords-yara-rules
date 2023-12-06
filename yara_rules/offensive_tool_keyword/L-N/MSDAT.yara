rule MSDAT
{
    meta:
        description = "Detection patterns for the tool 'MSDAT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MSDAT"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: MSDAT (Microsoft SQL Database Attacking Tool) is an open source penetration testing tool that tests the security of Microsoft SQL Databases remotely.
        // Reference: https://github.com/quentinhardy/msdat
        $string1 = /quentinhardy.{0,1000}msdat/ nocase ascii wide

    condition:
        any of them
}
