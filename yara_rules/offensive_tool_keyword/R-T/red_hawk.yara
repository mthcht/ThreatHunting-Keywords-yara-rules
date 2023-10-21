rule red_hawk
{
    meta:
        description = "Detection patterns for the tool 'red_hawk' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "red_hawk"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Vulnerability Scanning and Crawling. A must have tool for all penetration testers.
        // Reference: https://github.com/Tuhinshubhra/RED_HAWK
        $string1 = /RED_HAWK/ nocase ascii wide

    condition:
        any of them
}