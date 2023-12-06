rule NoSQLMap
{
    meta:
        description = "Detection patterns for the tool 'NoSQLMap' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NoSQLMap"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Automated NoSQL database enumeration and web application exploitation tool.
        // Reference: https://github.com/codingo/NoSQLMap
        $string1 = /NoSQLMap/ nocase ascii wide

    condition:
        any of them
}
