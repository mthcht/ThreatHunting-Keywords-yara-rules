rule P4wnP1
{
    meta:
        description = "Detection patterns for the tool 'P4wnP1' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "P4wnP1"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: P4wnP1 is a highly customizable USB attack platform. based on a low cost Raspberry Pi Zero or Raspberry Pi Zero W (required for HID backdoor).
        // Reference: https://github.com/RoganDawes/P4wnP1
        $string1 = /P4wnP1/ nocase ascii wide

    condition:
        any of them
}
