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
        $string1 = /\s\|\sFind\-AmsiSignatures/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string2 = /\s\|\sTest\-ContainsAmsiSignatures/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string3 = /\s\-ScriptString\s.{0,1000}\s\-GetMinimallyObfuscated/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string4 = /\s\-ScriptString\s.{0,1000}\s\-PSAmsiScanner\s/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string5 = /\s\-ServerUri\s.{0,1000}\s\-FindAmsiSignatures/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string6 = /\?PSAmsi.{0,1000}PSReflect\.ps1/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string7 = /cobbr\/PSAmsi/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string8 = /Find\-AmsiAstSignatures\s\-/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string9 = /Find\-AmsiPSTokenSignatures\s\-/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string10 = /Find\-AmsiSignatures\.ps1/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string11 = /Invoke\-PSAmsiScan/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string12 = /New\-PSAmsiScanner\s\-/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string13 = /Out\-ObfuscatedAst\.ps1/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string14 = /Out\-ObfuscatedStringCommand\.ps1/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string15 = /Out\-ObfuscatedTokenCommand\.ps1/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string16 = /PowerShellObfuscator\.ps1/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string17 = /PSAmsiClient\.ps1/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string18 = /PSAmsiScanner\.ps1/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string19 = /Start\-PSAmsiClient\.ps1/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string20 = /Start\-PSAmsiServer\.ps1/ nocase ascii wide
        // Description: PSAmsi is a tool for auditing and defeating AMSI signatures.
        // Reference: https://github.com/cobbr/PSAmsi
        $string21 = /Test\-ContainsAmsiPSTokenSignatures\s\-/ nocase ascii wide

    condition:
        any of them
}
