rule tir_blanc_holiseum
{
    meta:
        description = "Detection patterns for the tool 'tir_blanc_holiseum' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tir_blanc_holiseum"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Ransomware simulation
        // Reference: https://www.holiseum.com/services/auditer/tir-a-blanc-ransomware
        $string1 = /.{0,1000}\\tir_blanc_holiseum\\.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Ransomware simulation
        // Reference: https://www.holiseum.com/services/auditer/tir-a-blanc-ransomware
        $string2 = /.{0,1000}kindloader\.exe.{0,1000}\s\-\-extract\skindlocker.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
