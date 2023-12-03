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
        $string1 = /.{0,1000}\s\-\-CaCertPath\s.{0,1000}\.pfx\s\-\-CaCertPassword\s.{0,1000}/ nocase ascii wide
        // Description: ForgeCert uses the BouncyCastle C# API and a stolen Certificate Authority (CA) certificate + private key to forge certificates for arbitrary users capable of authentication to Active Directory.
        // Reference: https://github.com/GhostPack/ForgeCert
        $string2 = /.{0,1000}\s\-\-NewCertPath\s.{0,1000}\.pfx\s\-\-NewCertPassword\s.{0,1000}/ nocase ascii wide
        // Description: ForgeCert uses the BouncyCastle C# API and a stolen Certificate Authority (CA) certificate + private key to forge certificates for arbitrary users capable of authentication to Active Directory.
        // Reference: https://github.com/GhostPack/ForgeCert
        $string3 = /.{0,1000}\/ForgeCert\.git.{0,1000}/ nocase ascii wide
        // Description: ForgeCert uses the BouncyCastle C# API and a stolen Certificate Authority (CA) certificate + private key to forge certificates for arbitrary users capable of authentication to Active Directory.
        // Reference: https://github.com/GhostPack/ForgeCert
        $string4 = /.{0,1000}bd346689\-8ee6\-40b3\-858b\-4ed94f08d40a.{0,1000}/ nocase ascii wide
        // Description: ForgeCert uses the BouncyCastle C# API and a stolen Certificate Authority (CA) certificate + private key to forge certificates for arbitrary users capable of authentication to Active Directory.
        // Reference: https://github.com/GhostPack/ForgeCert
        $string5 = /.{0,1000}ForgeCert\-main.{0,1000}/ nocase ascii wide
        // Description: ForgeCert uses the BouncyCastle C# API and a stolen Certificate Authority (CA) certificate + private key to forge certificates for arbitrary users capable of authentication to Active Directory.
        // Reference: https://github.com/GhostPack/ForgeCert
        $string6 = /.{0,1000}GhostPack\/ForgeCert.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
