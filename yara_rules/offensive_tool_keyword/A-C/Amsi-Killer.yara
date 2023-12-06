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
        $string1 = /\/Amsi\-Killer\.git/ nocase ascii wide
        // Description: Lifetime AMSI bypass
        // Reference: https://github.com/ZeroMemoryEx/Amsi-Killer
        $string2 = /AMSI\spatched\sin\sall\spowershells/ nocase ascii wide
        // Description: Lifetime AMSI bypass
        // Reference: https://github.com/ZeroMemoryEx/Amsi-Killer
        $string3 = /Amsi\-Killer\.exe/ nocase ascii wide
        // Description: Lifetime AMSI bypass
        // Reference: https://github.com/ZeroMemoryEx/Amsi-Killer
        $string4 = /Amsi\-Killer\.sln/ nocase ascii wide
        // Description: Lifetime AMSI bypass
        // Reference: https://github.com/ZeroMemoryEx/Amsi-Killer
        $string5 = /Amsi\-Killer\.vcxproj/ nocase ascii wide
        // Description: Lifetime AMSI bypass
        // Reference: https://github.com/ZeroMemoryEx/Amsi-Killer
        $string6 = /Amsi\-Killer\-master/ nocase ascii wide
        // Description: Lifetime AMSI bypass
        // Reference: https://github.com/ZeroMemoryEx/Amsi-Killer
        $string7 = /E2E64E89\-8ACE\-4AA1\-9340\-8E987F5F142F/ nocase ascii wide
        // Description: Lifetime AMSI bypass
        // Reference: https://github.com/ZeroMemoryEx/Amsi-Killer
        $string8 = /ZeroMemoryEx\/Amsi\-Killer/ nocase ascii wide

    condition:
        any of them
}
