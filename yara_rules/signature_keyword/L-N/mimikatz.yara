rule mimikatz
{
    meta:
        description = "Detection patterns for the tool 'mimikatz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mimikatz"
        rule_category = "signature_keyword"

    strings:
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string1 = /Gen\:Variant\.Mimikatz/ nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string2 = /HackTool\.Mimikatz/ nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string3 = "HackTool/Mimikatz" nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string4 = "HackTool:Win32/Mimilove" nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string5 = /HEUR\:Trojan\-PSW\.Win64\.Mimilove/ nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string6 = "HKTL_MIMIKATZ" nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string7 = /Mimikatz\.Spyware\.Stealer\.DDS/ nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string8 = /Trojan\/Win\.Mimikatz/ nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string9 = /Trojan\-PSW\.Win64\.Mimilove/ nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string10 = /Win32\.Mimikatz/ nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string11 = /Win32\/Riskware\.Mimikatz/ nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string12 = /Win64\.Mimikatz/ nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string13 = "Win64/Riskware Mimikatz" nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string14 = /Win64\/Riskware\.Mimikatz/ nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string15 = /Win64\/Riskware\.Mimikatz/ nocase ascii wide

    condition:
        any of them
}
