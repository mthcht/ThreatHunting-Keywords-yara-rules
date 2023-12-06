rule Amsi_Bypass
{
    meta:
        description = "Detection patterns for the tool 'Amsi_Bypass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Amsi_Bypass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Amsi Bypass payload that works on Windwos 11
        // Reference: https://github.com/senzee1984/Amsi_Bypass_In_2023
        $string1 = /\/Amsi_Bypass_In_2023/ nocase ascii wide
        // Description: Amsi Bypass payload that works on Windwos 11
        // Reference: https://github.com/senzee1984/Amsi_Bypass_In_2023
        $string2 = /Attack_AmsiOpenSession\.ps1/ nocase ascii wide
        // Description: Amsi Bypass payload that works on Windwos 11
        // Reference: https://github.com/senzee1984/Amsi_Bypass_In_2023
        $string3 = /Attack_AmsiScanBuffer\.ps1/ nocase ascii wide

    condition:
        any of them
}
