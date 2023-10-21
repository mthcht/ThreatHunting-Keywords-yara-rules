rule RasmanPotato
{
    meta:
        description = "Detection patterns for the tool 'RasmanPotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RasmanPotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string1 = /\srasman\.exe/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string2 = /\/rasman\.exe/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string3 = /\/RasmanPotato/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string4 = /\\rasman\.exe/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string5 = /\\RasmanPotato/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string6 = /anypotato\.exe/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string7 = /magicRasMan/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string8 = /rasman.*whoami/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string9 = /RasMan\.cpp/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string10 = /RasMan\.sln/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string11 = /RasMan\.vcxproj/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string12 = /rasman_c\.c/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string13 = /rasman_h\.h/ nocase ascii wide
        // Description: using RasMan service for privilege escalation
        // Reference: https://github.com/crisprss/RasmanPotato
        $string14 = /RasmanPotato\-master/ nocase ascii wide

    condition:
        any of them
}