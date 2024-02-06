rule SharpShares
{
    meta:
        description = "Detection patterns for the tool 'SharpShares' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpShares"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string1 = /\/SharpShares\.git/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string2 = /\/SharpShares\-master/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string3 = /\[\+\]\sFinished\sEnumerating\sShares/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string4 = /\[\+\]\sQuerying\sDC\swithout\sGlobal\sCatalog\:\s/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string5 = /\\SharpShares\\/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string6 = /\\SharpShares\-master/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string7 = /\]\sStarting\sshare\senumeration\swith\sthread\slimit\sof\s/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string8 = /BCBC884D\-2D47\-4138\-B68F\-7D425C9291F9/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string9 = /execute\-assembly\s.{0,1000}\.exe\s\/ldap\:all\s\/filter\:sysvol.{0,1000}netlogon.{0,1000}ipc\$.{0,1000}print\$/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string10 = /Hackcraft\-Labs\/SharpShares/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/mitchmoser/SharpShares
        $string11 = /mitchmoser\/SharpShares/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string12 = /namespace\sSharpShares/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string13 = /SharpShares\.csproj/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string14 = /SharpShares\.exe/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string15 = /SharpShares\.sln/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string16 = /Starting\sshare\senumeration\sagainst\s.{0,1000}\shosts/ nocase ascii wide

    condition:
        any of them
}
