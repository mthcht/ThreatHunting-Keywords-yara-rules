rule CarbonCopy
{
    meta:
        description = "Detection patterns for the tool 'CarbonCopy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CarbonCopy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool which creates a spoofed certificate of any online website and signs an Executable for AV Evasion. Works for both Windows and Linux
        // Reference: https://github.com/paranoidninja/CarbonCopy
        $string1 = /CarbonCopy/ nocase ascii wide

    condition:
        any of them
}
