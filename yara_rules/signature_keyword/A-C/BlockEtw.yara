rule BlockEtw
{
    meta:
        description = "Detection patterns for the tool 'BlockEtw' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BlockEtw"
        rule_category = "signature_keyword"

    strings:
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string1 = "ATK/BlockETW-A" nocase ascii wide
        // Description: .Net Assembly to block ETW telemetry in current process
        // Reference: https://github.com/Soledge/BlockEtw
        $string2 = /Trojan\:Win32\/Rozena\.HNB\!MTB/ nocase ascii wide

    condition:
        any of them
}
