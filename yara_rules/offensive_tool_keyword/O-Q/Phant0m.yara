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
        $string1 = /.{0,1000}\/Phant0m\.git.{0,1000}/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string2 = /.{0,1000}\/phant0m\-exe.{0,1000}/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string3 = /.{0,1000}\\wmi_1\.dll.{0,1000}/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string4 = /.{0,1000}\\wmi_2\.dll.{0,1000}/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string5 = /.{0,1000}hlldz\/Phant0m.{0,1000}/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string6 = /.{0,1000}Invoke\-Phant0m\.ps1.{0,1000}/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string7 = /.{0,1000}Phant0m\sscm\s1.{0,1000}/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string8 = /.{0,1000}Phant0m\sscm\s2.{0,1000}/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string9 = /.{0,1000}Phant0m\swmi.{0,1000}/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string10 = /.{0,1000}phant0m\.cna.{0,1000}/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string11 = /.{0,1000}phant0m\-exe\..{0,1000}/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string12 = /.{0,1000}Phant0m\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string13 = /.{0,1000}phant0m\-rdll.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
