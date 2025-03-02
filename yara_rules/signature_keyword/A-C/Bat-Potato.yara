rule Bat_Potato
{
    meta:
        description = "Detection patterns for the tool 'Bat-Potato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Bat-Potato"
        rule_category = "signature_keyword"

    strings:
        // Description: Automating Juicy Potato Local Privilege Escalation CMD exploit for penetration testers
        // Reference: https://github.com/0x4xel/Bat-Potato
        $string1 = /\\Bat\-Potato\.bat/ nocase ascii wide
        // Description: Automating Juicy Potato Local Privilege Escalation CMD exploit for penetration testers
        // Reference: https://github.com/0x4xel/Bat-Potato
        $string2 = "ATK/JPotato-" nocase ascii wide
        // Description: Automating Juicy Potato Local Privilege Escalation CMD exploit for penetration testers
        // Reference: https://github.com/0x4xel/Bat-Potato
        $string3 = /HackTool\.JuicyPotato/ nocase ascii wide
        // Description: Automating Juicy Potato Local Privilege Escalation CMD exploit for penetration testers
        // Reference: https://github.com/0x4xel/Bat-Potato
        $string4 = /HackTool\.Win64\.JPotato/ nocase ascii wide
        // Description: Automating Juicy Potato Local Privilege Escalation CMD exploit for penetration testers
        // Reference: https://github.com/0x4xel/Bat-Potato
        $string5 = "HackTool:Win64/JuicyPotato" nocase ascii wide

    condition:
        any of them
}
