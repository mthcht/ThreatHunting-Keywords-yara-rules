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
        $string1 = /.{0,1000}\s\-IP\s.{0,1000}\s\-SpooferIP\s.{0,1000}\s\-HTTP\sN.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string2 = /.{0,1000}\s\-llmnrtypes\sAAAA.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string3 = /.{0,1000}\s\-mdns\sy\s\-mdnsunicast\sn.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string4 = /.{0,1000}\s\-NBNSBruteForce.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string5 = /.{0,1000}\s\-p:AssemblyName\=inveigh.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string6 = /.{0,1000}\.exe\s\-sniffer\sn.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string7 = /.{0,1000}\/Inveigh\.git.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string8 = /.{0,1000}\\Inveigh\.exe.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string9 = /.{0,1000}\\Inveigh\\bin\\.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string10 = /.{0,1000}dotnet\sInveigh\.dll.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string11 = /.{0,1000}Inveigh\.ps1.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string12 = /.{0,1000}Inveigh\.psd1.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string13 = /.{0,1000}Inveigh\.psm1.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string14 = /.{0,1000}Inveigh\.sln.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string15 = /.{0,1000}Inveigh\-Cleartext\.txt.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string16 = /.{0,1000}Inveigh\-FormInput\.txt.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string17 = /.{0,1000}Inveigh\-Log\.txt.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string18 = /.{0,1000}Inveigh\-master.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string19 = /.{0,1000}Inveigh\-net.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string20 = /.{0,1000}Inveigh\-NTLMv1\.txt.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string21 = /.{0,1000}Inveigh\-NTLMv2\.txt.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string22 = /.{0,1000}Inveigh\-Relay\.ps1.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string23 = /.{0,1000}inveighzero\.exe.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string24 = /.{0,1000}Invoke\-Inveigh.{0,1000}/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string25 = /.{0,1000}Kevin\-Robertson\/Inveigh.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
