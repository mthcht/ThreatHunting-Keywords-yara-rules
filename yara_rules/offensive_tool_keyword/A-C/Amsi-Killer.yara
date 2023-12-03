rule Amsi_Killer
{
    meta:
        description = "Detection patterns for the tool 'Amsi-Killer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Amsi-Killer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Lifetime AMSI bypass
        // Reference: https://github.com/ZeroMemoryEx/Amsi-Killer
        $string1 = /.{0,1000}\/Amsi\-Killer\.git.{0,1000}/ nocase ascii wide
        // Description: Lifetime AMSI bypass
        // Reference: https://github.com/ZeroMemoryEx/Amsi-Killer
        $string2 = /.{0,1000}AMSI\spatched\sin\sall\spowershells.{0,1000}/ nocase ascii wide
        // Description: Lifetime AMSI bypass
        // Reference: https://github.com/ZeroMemoryEx/Amsi-Killer
        $string3 = /.{0,1000}Amsi\-Killer\.exe.{0,1000}/ nocase ascii wide
        // Description: Lifetime AMSI bypass
        // Reference: https://github.com/ZeroMemoryEx/Amsi-Killer
        $string4 = /.{0,1000}Amsi\-Killer\.sln.{0,1000}/ nocase ascii wide
        // Description: Lifetime AMSI bypass
        // Reference: https://github.com/ZeroMemoryEx/Amsi-Killer
        $string5 = /.{0,1000}Amsi\-Killer\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: Lifetime AMSI bypass
        // Reference: https://github.com/ZeroMemoryEx/Amsi-Killer
        $string6 = /.{0,1000}Amsi\-Killer\-master.{0,1000}/ nocase ascii wide
        // Description: Lifetime AMSI bypass
        // Reference: https://github.com/ZeroMemoryEx/Amsi-Killer
        $string7 = /.{0,1000}E2E64E89\-8ACE\-4AA1\-9340\-8E987F5F142F.{0,1000}/ nocase ascii wide
        // Description: Lifetime AMSI bypass
        // Reference: https://github.com/ZeroMemoryEx/Amsi-Killer
        $string8 = /.{0,1000}ZeroMemoryEx\/Amsi\-Killer.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
