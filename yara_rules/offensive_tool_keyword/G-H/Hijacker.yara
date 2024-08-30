rule Hijacker
{
    meta:
        description = "Detection patterns for the tool 'Hijacker' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hijacker"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Hijacker is a Graphical User Interface for the penetration testing tools Aircrack-ng. Airodump-ng. MDK3 and Reaver.
        // Reference: https://github.com/chrisk44/Hijacker
        $string1 = /Hijacker/ nocase ascii wide

    condition:
        any of them
}
