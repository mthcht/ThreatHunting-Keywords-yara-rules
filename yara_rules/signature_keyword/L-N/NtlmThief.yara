rule NtlmThief
{
    meta:
        description = "Detection patterns for the tool 'NtlmThief' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NtlmThief"
        rule_category = "signature_keyword"

    strings:
        // Description: Extracting NetNTLM without touching lsass.exe
        // Reference: https://github.com/MzHmO/NtlmThief
        $string1 = /HEUR\:Trojan\-PSW\.Win64\.NTLM\.gen/ nocase ascii wide

    condition:
        any of them
}
