rule PSAmsi
{
    meta:
        description = "Detection patterns for the tool 'PSAmsi' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSAmsi"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string1 = /.{0,1000}\s\|\sFind\-AmsiSignatures.{0,1000}/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string2 = /.{0,1000}\s\|\sTest\-ContainsAmsiSignatures.{0,1000}/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string3 = /.{0,1000}\s\-ScriptString\s.{0,1000}\s\-GetMinimallyObfuscated.{0,1000}/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string4 = /.{0,1000}\s\-ScriptString\s.{0,1000}\s\-PSAmsiScanner\s.{0,1000}/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string5 = /.{0,1000}\s\-ServerUri\s.{0,1000}\s\-FindAmsiSignatures.{0,1000}/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string6 = /.{0,1000}\?PSAmsi.{0,1000}PSReflect\.ps1.{0,1000}/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string7 = /.{0,1000}cobbr\/PSAmsi.{0,1000}/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string8 = /.{0,1000}Find\-AmsiAstSignatures\s\-.{0,1000}/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string9 = /.{0,1000}Find\-AmsiPSTokenSignatures\s\-.{0,1000}/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string10 = /.{0,1000}Find\-AmsiSignatures\.ps1.{0,1000}/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string11 = /.{0,1000}Invoke\-PSAmsiScan.{0,1000}/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string12 = /.{0,1000}New\-PSAmsiScanner\s\-.{0,1000}/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string13 = /.{0,1000}Out\-ObfuscatedAst\.ps1.{0,1000}/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string14 = /.{0,1000}Out\-ObfuscatedStringCommand\.ps1.{0,1000}/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string15 = /.{0,1000}Out\-ObfuscatedTokenCommand\.ps1.{0,1000}/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string16 = /.{0,1000}PowerShellObfuscator\.ps1.{0,1000}/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string17 = /.{0,1000}PSAmsiClient\.ps1.{0,1000}/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string18 = /.{0,1000}PSAmsiScanner\.ps1.{0,1000}/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string19 = /.{0,1000}Start\-PSAmsiClient\.ps1.{0,1000}/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string20 = /.{0,1000}Start\-PSAmsiServer\.ps1.{0,1000}/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string21 = /.{0,1000}Test\-ContainsAmsiPSTokenSignatures\s\-.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
