rule BetterBackdoor
{
    meta:
        description = "Detection patterns for the tool 'BetterBackdoor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BetterBackdoor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A backdoor is a tool used to gain remote access to a machine.
        // Reference: https://github.com/thatcherclough/BetterBackdoor
        $string1 = /BetterBackdoor/ nocase ascii wide

    condition:
        any of them
}
