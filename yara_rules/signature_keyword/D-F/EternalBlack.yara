rule EternalBlack
{
    meta:
        description = "Detection patterns for the tool 'EternalBlack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EternalBlack"
        rule_category = "signature_keyword"

    strings:
        // Description: EternalRomance exploit implemented by Playbit EternalBlack often used by ransomware group like Dispossessor
        // Reference: https://research.checkpoint.com/2020/graphology-of-an-exploit-playbit/
        $string1 = /Trojan\.Meterpreter/ nocase ascii wide
        // Description: EternalRomance exploit implemented by Playbit EternalBlack often used by ransomware group like Dispossessor
        // Reference: https://research.checkpoint.com/2020/graphology-of-an-exploit-playbit/
        $string2 = "Trojan:Win64/Meterpreter" nocase ascii wide

    condition:
        any of them
}
