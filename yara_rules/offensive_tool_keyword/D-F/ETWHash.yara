rule ETWHash
{
    meta:
        description = "Detection patterns for the tool 'ETWHash' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ETWHash"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C# POC to extract NetNTLMv1/v2 hashes from ETW provider
        // Reference: https://github.com/nettitude/ETWHash
        $string1 = /\sEtwHash/ nocase ascii wide
        // Description: C# POC to extract NetNTLMv1/v2 hashes from ETW provider
        // Reference: https://github.com/nettitude/ETWHash
        $string2 = /\/ETWHash\// nocase ascii wide
        // Description: C# POC to extract NetNTLMv1/v2 hashes from ETW provider
        // Reference: https://github.com/nettitude/ETWHash
        $string3 = /\\ETWHash\./ nocase ascii wide
        // Description: C# POC to extract NetNTLMv1/v2 hashes from ETW provider
        // Reference: https://github.com/nettitude/ETWHash
        $string4 = /EtwHash\.exe/ nocase ascii wide
        // Description: C# POC to extract NetNTLMv1/v2 hashes from ETW provider
        // Reference: https://github.com/nettitude/ETWHash
        $string5 = /EtwHash\.git/ nocase ascii wide
        // Description: C# POC to extract NetNTLMv1/v2 hashes from ETW provider
        // Reference: https://github.com/nettitude/ETWHash
        $string6 = /ETWHash\.sln/ nocase ascii wide
        // Description: C# POC to extract NetNTLMv1/v2 hashes from ETW provider
        // Reference: https://github.com/nettitude/ETWHash
        $string7 = /nettitude\/ETWHash/ nocase ascii wide

    condition:
        any of them
}
