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
        $string1 = /.{0,1000}\sEtwHash.{0,1000}/ nocase ascii wide
        // Description: C# POC to extract NetNTLMv1/v2 hashes from ETW provider
        // Reference: https://github.com/nettitude/ETWHash
        $string2 = /.{0,1000}\/ETWHash\/.{0,1000}/ nocase ascii wide
        // Description: C# POC to extract NetNTLMv1/v2 hashes from ETW provider
        // Reference: https://github.com/nettitude/ETWHash
        $string3 = /.{0,1000}\\ETWHash\..{0,1000}/ nocase ascii wide
        // Description: C# POC to extract NetNTLMv1/v2 hashes from ETW provider
        // Reference: https://github.com/nettitude/ETWHash
        $string4 = /.{0,1000}EtwHash\.exe.{0,1000}/ nocase ascii wide
        // Description: C# POC to extract NetNTLMv1/v2 hashes from ETW provider
        // Reference: https://github.com/nettitude/ETWHash
        $string5 = /.{0,1000}EtwHash\.git.{0,1000}/ nocase ascii wide
        // Description: C# POC to extract NetNTLMv1/v2 hashes from ETW provider
        // Reference: https://github.com/nettitude/ETWHash
        $string6 = /.{0,1000}ETWHash\.sln.{0,1000}/ nocase ascii wide
        // Description: C# POC to extract NetNTLMv1/v2 hashes from ETW provider
        // Reference: https://github.com/nettitude/ETWHash
        $string7 = /.{0,1000}nettitude\/ETWHash.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
