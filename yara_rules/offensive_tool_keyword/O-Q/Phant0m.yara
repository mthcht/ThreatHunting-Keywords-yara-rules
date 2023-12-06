rule Phant0m
{
    meta:
        description = "Detection patterns for the tool 'Phant0m' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Phant0m"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string1 = /\/Phant0m\.git/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string2 = /\/phant0m\-exe/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string3 = /\\wmi_1\.dll/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string4 = /\\wmi_2\.dll/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string5 = /hlldz\/Phant0m/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string6 = /Invoke\-Phant0m\.ps1/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string7 = /Phant0m\sscm\s1/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string8 = /Phant0m\sscm\s2/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string9 = /Phant0m\swmi/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string10 = /phant0m\.cna/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string11 = /phant0m\-exe\./ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string12 = /Phant0m\-master\.zip/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string13 = /phant0m\-rdll/ nocase ascii wide

    condition:
        any of them
}
