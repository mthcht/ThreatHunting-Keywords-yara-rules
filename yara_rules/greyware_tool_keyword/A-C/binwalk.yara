rule binwalk
{
    meta:
        description = "Detection patterns for the tool 'binwalk' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "binwalk"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Binwalk is a fast. easy to use tool for analyzing. reverse engineering. and extracting firmware images.
        // Reference: https://github.com/ReFirmLabs/binwalk
        $string1 = /binwalk/ nocase ascii wide

    condition:
        any of them
}
