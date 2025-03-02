rule SharpZeroLogon
{
    meta:
        description = "Detection patterns for the tool 'SharpZeroLogon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpZeroLogon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: exploit for CVE-2020-1472
        // Reference: https://github.com/leitosama/SharpZeroLogon
        $string1 = /\/SharpZeroLogon\.git/ nocase ascii wide
        // Description: exploit for CVE-2020-1472
        // Reference: https://github.com/leitosama/SharpZeroLogon
        $string2 = /\\SharpZeroLogon\.sln/ nocase ascii wide
        // Description: exploit for CVE-2020-1472
        // Reference: https://github.com/leitosama/SharpZeroLogon
        $string3 = ">SharpZeroLogon<" nocase ascii wide
        // Description: exploit for CVE-2020-1472
        // Reference: https://github.com/leitosama/SharpZeroLogon
        $string4 = "0bef49d95cf04914b2824fe3957dc3b9f66447c150877254ddbbf36dd7b231b8" nocase ascii wide
        // Description: exploit for CVE-2020-1472
        // Reference: https://github.com/leitosama/SharpZeroLogon
        $string5 = "15ce9a3c-4609-4184-87b2-e29fc5e2b770" nocase ascii wide
        // Description: exploit for CVE-2020-1472
        // Reference: https://github.com/leitosama/SharpZeroLogon
        $string6 = "465a8ba788d324313ccf9d344f35ce5d1d4153d0367c6f647bfa817be18934ce" nocase ascii wide
        // Description: exploit for CVE-2020-1472
        // Reference: https://github.com/leitosama/SharpZeroLogon
        $string7 = "leitosama/SharpZeroLogon" nocase ascii wide
        // Description: exploit for CVE-2020-1472
        // Reference: https://github.com/leitosama/SharpZeroLogon
        $string8 = /SharpZeroLogon\.exe/ nocase ascii wide
        // Description: exploit for CVE-2020-1472
        // Reference: https://github.com/leitosama/SharpZeroLogon
        $string9 = "Success! DC can be fully compromised by a Zerologon attack" nocase ascii wide

    condition:
        any of them
}
