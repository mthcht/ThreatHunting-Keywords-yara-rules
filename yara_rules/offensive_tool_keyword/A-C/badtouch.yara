rule badtouch
{
    meta:
        description = "Detection patterns for the tool 'badtouch' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "badtouch"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Scriptable network authentication cracker
        // Reference: https://github.com/kpcyrd/badtouch
        $string1 = /kpcyrd\/badtouch/ nocase ascii wide

    condition:
        any of them
}
