rule Inveigh
{
    meta:
        description = "Detection patterns for the tool 'Inveigh' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Inveigh"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string1 = /\s\-IP\s.{0,1000}\s\-SpooferIP\s.{0,1000}\s\-HTTP\sN/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string2 = /\s\-llmnrtypes\sAAAA/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string3 = /\s\-mdns\sy\s\-mdnsunicast\sn/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string4 = /\s\-NBNSBruteForce/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string5 = /\s\-p\:AssemblyName\=inveigh/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string6 = /\.exe\s\-sniffer\sn/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string7 = /\/Inveigh\.git/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string8 = /\\Inveigh\.exe/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string9 = /\\Inveigh\\bin\\/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string10 = /dotnet\sInveigh\.dll/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string11 = /Inveigh\.ps1/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string12 = /Inveigh\.psd1/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string13 = /Inveigh\.psm1/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string14 = /Inveigh\.sln/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string15 = /Inveigh\-Cleartext\.txt/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string16 = /Inveigh\-FormInput\.txt/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string17 = /Inveigh\-Log\.txt/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string18 = /Inveigh\-master/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string19 = /Inveigh\-net.{0,1000}\.zip/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string20 = /Inveigh\-NTLMv1\.txt/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string21 = /Inveigh\-NTLMv2\.txt/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string22 = /Inveigh\-Relay\.ps1/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string23 = /inveighzero\.exe/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string24 = /Invoke\-Inveigh/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string25 = /Kevin\-Robertson\/Inveigh/ nocase ascii wide

    condition:
        any of them
}
