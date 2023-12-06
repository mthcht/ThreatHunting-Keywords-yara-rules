rule Anevicon
{
    meta:
        description = "Detection patterns for the tool 'Anevicon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Anevicon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Attack simulation: Anevicon is a high-performance traffic generator. designed to be as convenient and reliable as it is possible. It sends numerous UDP-packets to a victim. thereby simulating an activity that can be produced by your end users or a group of hackers.
        // Reference: https://github.com/rozgo/anevicon
        $string1 = /Anevicon/ nocase ascii wide

    condition:
        any of them
}
