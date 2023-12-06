rule Weevely3
{
    meta:
        description = "Detection patterns for the tool 'Weevely3' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Weevely3"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Webponized web shell
        // Reference: https://github.com/epinna/weevely3
        $string1 = /\/Weevely3/ nocase ascii wide

    condition:
        any of them
}
