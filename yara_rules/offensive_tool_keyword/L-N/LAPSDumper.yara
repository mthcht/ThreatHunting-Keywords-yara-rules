rule LAPSDumper
{
    meta:
        description = "Detection patterns for the tool 'LAPSDumper' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LAPSDumper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dumping LAPS from Python
        // Reference: https://github.com/n00py/LAPSDumper
        $string1 = /.{0,1000}\slaps\.py\s.{0,1000}\-\-ldapserver.{0,1000}/ nocase ascii wide
        // Description: Dumping LAPS from Python
        // Reference: https://github.com/n00py/LAPSDumper
        $string2 = /.{0,1000}\slaps\.py\s.{0,1000}\-u\s.{0,1000}\s\-p\s.{0,1000}/ nocase ascii wide
        // Description: Dumping LAPS from Python
        // Reference: https://github.com/n00py/LAPSDumper
        $string3 = /.{0,1000}\/laps\.py\s.{0,1000}\-\-ldapserver.{0,1000}/ nocase ascii wide
        // Description: Dumping LAPS from Python
        // Reference: https://github.com/n00py/LAPSDumper
        $string4 = /.{0,1000}\/laps\.py\s.{0,1000}\-u\s.{0,1000}\s\-p\s.{0,1000}/ nocase ascii wide
        // Description: Dumping LAPS from Python
        // Reference: https://github.com/n00py/LAPSDumper
        $string5 = /.{0,1000}\/LAPSDumper\.git.{0,1000}/ nocase ascii wide
        // Description: Dumping LAPS from Python
        // Reference: https://github.com/n00py/LAPSDumper
        $string6 = /.{0,1000}\\LAPSDumper\\.{0,1000}/ nocase ascii wide
        // Description: Dumping LAPS from Python
        // Reference: https://github.com/n00py/LAPSDumper
        $string7 = /.{0,1000}LAPSDumper\-main.{0,1000}/ nocase ascii wide
        // Description: Dumping LAPS from Python
        // Reference: https://github.com/n00py/LAPSDumper
        $string8 = /.{0,1000}n00py\/LAPSDumper.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
