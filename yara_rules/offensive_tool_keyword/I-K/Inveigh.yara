rule Inveigh
{
    meta:
        description = "Detection patterns for the tool 'Inveigh' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Inveigh"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string1 = /\sInveigh\.ps1/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string2 = /\s\-IP\s.{0,1000}\s\-SpooferIP\s.{0,1000}\s\-HTTP\sN/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string3 = /\s\-llmnrtypes\sAAAA/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string4 = /\s\-mdns\sy\s\-mdnsunicast\sn/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string5 = /\s\-NBNSBruteForce/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string6 = /\s\-p\:AssemblyName\=inveigh/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string7 = /\.exe\s\-sniffer\sn/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string8 = /\/Inveigh\.git/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string9 = /\/Inveigh\.ps1/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string10 = /\/Inveigh\-Cleartext\.txt/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string11 = /\/Inveigh\-FormInput\.txt/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string12 = /\/Inveigh\-Log\.txt/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string13 = /\/Inveigh\-NTLMv1\.txt/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string14 = /\/Inveigh\-NTLMv2\.txt/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string15 = /\\Inveigh\.exe/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string16 = /\\inveigh\.log/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string17 = /\\Inveigh\.ps1/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string18 = /\\Inveigh\.psd1/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string19 = /\\Inveigh\\bin\\/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string20 = /\\Inveigh\-Cleartext\.txt/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string21 = /\\Inveigh\-FormInput\.txt/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string22 = /\\Inveigh\-Log\.txt/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string23 = /\\Inveigh\-NTLMv1\.txt/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string24 = /\\Inveigh\-NTLMv2\.txt/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string25 = /dotnet\sInveigh\.dll/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string26 = /Inveigh\.ps1/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string27 = /Inveigh\.psd1/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string28 = /Inveigh\.psm1/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string29 = /Inveigh\.sln/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string30 = /Inveigh\-Cleartext\.txt/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string31 = /Inveigh\-FormInput\.txt/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string32 = /Inveigh\-Log\.txt/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string33 = /Inveigh\-master/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string34 = /Inveigh\-net.{0,1000}\.zip/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string35 = /Inveigh\-NTLMv1\.txt/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string36 = /Inveigh\-NTLMv2\.txt/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string37 = /Inveigh\-Relay\.ps1/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string38 = /inveighzero\.exe/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string39 = /Invoke\-Inveigh/ nocase ascii wide
        // Description: .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
        // Reference: https://github.com/Kevin-Robertson/Inveigh
        $string40 = /Kevin\-Robertson\/Inveigh/ nocase ascii wide

    condition:
        any of them
}
