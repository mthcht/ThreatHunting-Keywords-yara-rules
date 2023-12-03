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
        $string1 = /.{0,1000}\/SharpShares\.git.{0,1000}/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string2 = /.{0,1000}\/SharpShares\-master.{0,1000}/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string3 = /.{0,1000}\[\+\]\sFinished\sEnumerating\sShares.{0,1000}/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string4 = /.{0,1000}\[\+\]\sQuerying\sDC\swithout\sGlobal\sCatalog:\s.{0,1000}/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string5 = /.{0,1000}\\SharpShares\\.{0,1000}/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string6 = /.{0,1000}\\SharpShares\-master.{0,1000}/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string7 = /.{0,1000}\]\sStarting\sshare\senumeration\swith\sthread\slimit\sof\s.{0,1000}/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string8 = /.{0,1000}BCBC884D\-2D47\-4138\-B68F\-7D425C9291F9.{0,1000}/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string9 = /.{0,1000}execute\-assembly\s.{0,1000}\.exe\s\/ldap:all\s\/filter:sysvol.{0,1000}netlogon.{0,1000}ipc\$.{0,1000}print\$.{0,1000}/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string10 = /.{0,1000}Hackcraft\-Labs\/SharpShares.{0,1000}/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/mitchmoser/SharpShares
        $string11 = /.{0,1000}mitchmoser\/SharpShares.{0,1000}/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string12 = /.{0,1000}namespace\sSharpShares.{0,1000}/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string13 = /.{0,1000}SharpShares\.csproj.{0,1000}/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string14 = /.{0,1000}SharpShares\.exe.{0,1000}/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string15 = /.{0,1000}SharpShares\.sln.{0,1000}/ nocase ascii wide
        // Description: Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain
        // Reference: https://github.com/Hackcraft-Labs/SharpShares
        $string16 = /.{0,1000}Starting\sshare\senumeration\sagainst\s.{0,1000}\shosts.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
