rule novelbfh
{
    meta:
        description = "Detection patterns for the tool 'novelbfh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "novelbfh"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Brute force Novell hacking tool -- Circa 1993
        // Reference: https://github.com/nyxgeek/classic_hacking_tools
        $string1 = /novelbfh\.zip/ nocase ascii wide

    condition:
        any of them
}
