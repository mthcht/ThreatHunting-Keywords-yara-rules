rule SharpPersistSD
{
    meta:
        description = "Detection patterns for the tool 'SharpPersistSD' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpPersistSD"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string1 = /\sSharpPersistSD\.dll/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string2 = /\/SharpPersistSD\.dll/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string3 = /\/SharpPersistSD\.git/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string4 = /\[\+\]\sUsing\sWMI\sto\sset\sWMI\sSD/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string5 = /\\SharpPersistSD\.cs/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string6 = /\\SharpPersistSD\.dll/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string7 = /\\SharpPersistSD\.sln/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string8 = /107EBC1B\-0273\-4B3D\-B676\-DE64B7F52B33/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string9 = /1db1f717560d1c53a8ec668a80aad419da22a84b1705f7dfbcc3075634634f64/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string10 = /cybersectroll\/SharpPersistSD/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string11 = /e3e2ced2569d1ebef8f65b554979747881e5e060355fa6698c913036dfd892ba/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string12 = /f44bdc821e6588197e6d1b868a60aa140f20971a6eaeeb9e2a52bdb4065b7fd7/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string13 = /f93389056fa9ad53e214a468aa495adcb2ff1b75a64cd7df77a63a173066d05a/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string14 = /net\slocalgroup\sadministrators\s\/add\stroll/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string15 = /net\susers\s\/add\stroll\sTrolololol123/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string16 = /SharpPersistSD\.RegHelper/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string17 = /SharpPersistSD\.SecurityDescriptor/ nocase ascii wide
        // Description: A Post-Compromise granular .NET library to embed persistency to persistency by abusing Security Descriptors of remote machines
        // Reference: https://github.com/cybersectroll/SharpPersistSD
        $string18 = /SharpPersistSD\.SvcHelper/ nocase ascii wide

    condition:
        any of them
}
