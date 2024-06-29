rule set
{
    meta:
        description = "Detection patterns for the tool 'set' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "set"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Bitwise XOR Operation in commandline observed in a malware sample
        // Reference: https://tria.ge/240617-mn75pa1cnl/behavioral2/analog?proc=87
        $string1 = /cmd\s\/c\sset\s\/A\s1\^\^0/ nocase ascii wide
        // Description: Bitwise XOR Operation in commandline observed in a malware sample
        // Reference: https://tria.ge/240617-mn75pa1cnl/behavioral2/analog?proc=87
        $string2 = /cmd\.exe\s\/c\sset\s\/A\s1\^\^0/ nocase ascii wide
        // Description: Bitwise XOR Operation in commandline observed in a malware sample
        // Reference: https://tria.ge/240617-mn75pa1cnl/behavioral2/analog?proc=87
        $string3 = /cmd\.exe.{0,1000}\/c\sset\s\/A\s1\^\^0/ nocase ascii wide
        // Description: Does not write any of the current session to the history log
        // Reference: N/A
        $string4 = /set\s\+o\shistory/ nocase ascii wide

    condition:
        any of them
}
