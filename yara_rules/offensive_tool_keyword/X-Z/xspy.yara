rule xspy
{
    meta:
        description = "Detection patterns for the tool 'xspy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xspy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Keylogger Monitors keystrokes even the keyboard is grabbed.
        // Reference: https://github.com/mnp/xspy/blob/master/xspy.c
        $string1 = /xspy\s\-display/ nocase ascii wide

    condition:
        any of them
}
