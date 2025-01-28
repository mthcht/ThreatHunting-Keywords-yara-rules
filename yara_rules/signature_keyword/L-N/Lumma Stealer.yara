rule Lumma_Stealer
{
    meta:
        description = "Detection patterns for the tool 'Lumma Stealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lumma Stealer"
        rule_category = "signature_keyword"

    strings:
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string1 = "Trojan:Win64/Lumma" nocase ascii wide

    condition:
        any of them
}
