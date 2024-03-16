rule ired_team
{
    meta:
        description = "Detection patterns for the tool 'ired.team' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ired.team"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Red Teaming Tactics and Techniques
        // Reference: https://github.com/mantvydasb/RedTeaming-Tactics-and-Techniques
        $string1 = /\/RedTeaming\-Tactics\-and\-Techniques\.git/ nocase ascii wide
        // Description: Red Teaming Tactics and Techniques
        // Reference: https://github.com/mantvydasb/RedTeaming-Tactics-and-Techniques
        $string2 = /\\RedTeaming\-Tactics\-and\-Techniques\-master/ nocase ascii wide
        // Description: Red Teaming Tactics and Techniques
        // Reference: https://github.com/mantvydasb/RedTeaming-Tactics-and-Techniques
        $string3 = /mantvydasb\/RedTeaming\-Tactics\-and\-Techniques/ nocase ascii wide
        // Description: Red Teaming Tactics and Techniques
        // Reference: https://github.com/mantvydasb/RedTeaming-Tactics-and-Techniques
        $string4 = /www\.ired\.team/ nocase ascii wide

    condition:
        any of them
}
