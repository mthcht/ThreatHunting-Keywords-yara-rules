rule ForgeCert
{
    meta:
        description = "Detection patterns for the tool 'ForgeCert' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ForgeCert"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ForgeCert uses the BouncyCastle C# API and a stolen Certificate Authority (CA) certificate + private key to forge certificates for arbitrary users capable of authentication to Active Directory.
        // Reference: https://github.com/GhostPack/ForgeCert
        $string1 = /\s\-\-CaCertPath\s.{0,1000}\.pfx\s\-\-CaCertPassword\s/ nocase ascii wide
        // Description: ForgeCert uses the BouncyCastle C# API and a stolen Certificate Authority (CA) certificate + private key to forge certificates for arbitrary users capable of authentication to Active Directory.
        // Reference: https://github.com/GhostPack/ForgeCert
        $string2 = /\s\-\-NewCertPath\s.{0,1000}\.pfx\s\-\-NewCertPassword\s/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string3 = /\/ForgeCert\.exe/ nocase ascii wide
        // Description: ForgeCert uses the BouncyCastle C# API and a stolen Certificate Authority (CA) certificate + private key to forge certificates for arbitrary users capable of authentication to Active Directory.
        // Reference: https://github.com/GhostPack/ForgeCert
        $string4 = /\/ForgeCert\.git/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string5 = /\\ForgeCert\.exe/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string6 = /\\ForgeCert\.pdb/ nocase ascii wide
        // Description: ForgeCert uses the BouncyCastle C# API and a stolen Certificate Authority (CA) certificate + private key to forge certificates for arbitrary users capable of authentication to Active Directory.
        // Reference: https://github.com/GhostPack/ForgeCert
        $string7 = "bd346689-8ee6-40b3-858b-4ed94f08d40a" nocase ascii wide
        // Description: ForgeCert uses the BouncyCastle C# API and a stolen Certificate Authority (CA) certificate + private key to forge certificates for arbitrary users capable of authentication to Active Directory.
        // Reference: https://github.com/GhostPack/ForgeCert
        $string8 = "ForgeCert-main" nocase ascii wide
        // Description: ForgeCert uses the BouncyCastle C# API and a stolen Certificate Authority (CA) certificate + private key to forge certificates for arbitrary users capable of authentication to Active Directory.
        // Reference: https://github.com/GhostPack/ForgeCert
        $string9 = "GhostPack/ForgeCert" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string10 = "'Product'>ForgeCert" nocase ascii wide

    condition:
        any of them
}
