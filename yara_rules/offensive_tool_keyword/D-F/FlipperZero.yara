rule FlipperZero
{
    meta:
        description = "Detection patterns for the tool 'FlipperZero' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FlipperZero"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Flipper ZeroFlipper Zero is a portable multi-tool for pentesters and geeks in a toy-like body
        // Reference: https://docs.flipper.net/qflipper/windows-debug
        $string1 = /VID_0483\&PID_5740/ nocase ascii wide

    condition:
        any of them
}
