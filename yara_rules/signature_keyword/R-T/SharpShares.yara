rule SharpShares
{
    meta:
        description = "Detection patterns for the tool 'SharpShares' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpShares"
        rule_category = "signature_keyword"

    strings:
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/mitchmoser/SharpShares
        $string1 = /HackTool\.MSIL\.SharpShares/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/mitchmoser/SharpShares
        $string2 = /Hacktool\.Sharpshare/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/mitchmoser/SharpShares
        $string3 = /Tool\.SharpSharesNET/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/mitchmoser/SharpShares
        $string4 = /Windows\.Hacktool\.SharpShares/ nocase ascii wide

    condition:
        any of them
}
