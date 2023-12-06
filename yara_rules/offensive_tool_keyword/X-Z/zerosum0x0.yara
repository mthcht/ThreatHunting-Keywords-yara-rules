rule zerosum0x0
{
    meta:
        description = "Detection patterns for the tool 'zerosum0x0' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "zerosum0x0"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: github repo username hosting backdoors pocs and exploitation tools
        // Reference: https://github.com/zerosum0x0
        $string1 = /zerosum0x0/ nocase ascii wide

    condition:
        any of them
}
