rule locate
{
    meta:
        description = "Detection patterns for the tool 'locate' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "locate"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Find sensitive files
        // Reference: N/A
        $string1 = /locate\spassword\s\|\smore/ nocase ascii wide

    condition:
        any of them
}
