rule SharpAltSecIds
{
    meta:
        description = "Detection patterns for the tool 'SharpAltSecIds' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpAltSecIds"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Shadow Credentials via altSecurityIdentities - Enables attackers to add altSecurityIdentities entries to an account - linking it to an X.509 certificate for authentication. This allows them to impersonate the targeted account and authenticate using the associated certificate
        // Reference: https://github.com/bugch3ck/SharpAltSecIds
        $string1 = /\sadd\s\/target\:.{0,1000}\s\/altsecid\:X509\:/ nocase ascii wide
        // Description: Shadow Credentials via altSecurityIdentities - Enables attackers to add altSecurityIdentities entries to an account - linking it to an X.509 certificate for authentication. This allows them to impersonate the targeted account and authenticate using the associated certificate
        // Reference: https://github.com/bugch3ck/SharpAltSecIds
        $string2 = /\/SharpAltSecIds\.exe/ nocase ascii wide
        // Description: Shadow Credentials via altSecurityIdentities - Enables attackers to add altSecurityIdentities entries to an account - linking it to an X.509 certificate for authentication. This allows them to impersonate the targeted account and authenticate using the associated certificate
        // Reference: https://github.com/bugch3ck/SharpAltSecIds
        $string3 = /\/SharpAltSecIds\.git/ nocase ascii wide
        // Description: Shadow Credentials via altSecurityIdentities - Enables attackers to add altSecurityIdentities entries to an account - linking it to an X.509 certificate for authentication. This allows them to impersonate the targeted account and authenticate using the associated certificate
        // Reference: https://github.com/bugch3ck/SharpAltSecIds
        $string4 = /\[\+\]\sAdded\s\{altsecid\}\sto\s\{target\}/ nocase ascii wide
        // Description: Shadow Credentials via altSecurityIdentities - Enables attackers to add altSecurityIdentities entries to an account - linking it to an X.509 certificate for authentication. This allows them to impersonate the targeted account and authenticate using the associated certificate
        // Reference: https://github.com/bugch3ck/SharpAltSecIds
        $string5 = /\\SharpAltSecIds\.exe/ nocase ascii wide
        // Description: Shadow Credentials via altSecurityIdentities - Enables attackers to add altSecurityIdentities entries to an account - linking it to an X.509 certificate for authentication. This allows them to impersonate the targeted account and authenticate using the associated certificate
        // Reference: https://github.com/bugch3ck/SharpAltSecIds
        $string6 = /\\SharpAltSecIds\.sln/ nocase ascii wide
        // Description: Shadow Credentials via altSecurityIdentities - Enables attackers to add altSecurityIdentities entries to an account - linking it to an X.509 certificate for authentication. This allows them to impersonate the targeted account and authenticate using the associated certificate
        // Reference: https://github.com/bugch3ck/SharpAltSecIds
        $string7 = /\\SharpAltSecIds\-master/ nocase ascii wide
        // Description: Shadow Credentials via altSecurityIdentities - Enables attackers to add altSecurityIdentities entries to an account - linking it to an X.509 certificate for authentication. This allows them to impersonate the targeted account and authenticate using the associated certificate
        // Reference: https://github.com/bugch3ck/SharpAltSecIds
        $string8 = ">SharpAltSecIds<" nocase ascii wide
        // Description: Shadow Credentials via altSecurityIdentities - Enables attackers to add altSecurityIdentities entries to an account - linking it to an X.509 certificate for authentication. This allows them to impersonate the targeted account and authenticate using the associated certificate
        // Reference: https://github.com/bugch3ck/SharpAltSecIds
        $string9 = "5e00926cb43b56a330532ce5c4f0988172d49d28840ed490526976a7b2ea2479" nocase ascii wide
        // Description: Shadow Credentials via altSecurityIdentities - Enables attackers to add altSecurityIdentities entries to an account - linking it to an X.509 certificate for authentication. This allows them to impersonate the targeted account and authenticate using the associated certificate
        // Reference: https://github.com/bugch3ck/SharpAltSecIds
        $string10 = "623F0079-5871-4237-B872-70FDFC2D8C52" nocase ascii wide
        // Description: Shadow Credentials via altSecurityIdentities - Enables attackers to add altSecurityIdentities entries to an account - linking it to an X.509 certificate for authentication. This allows them to impersonate the targeted account and authenticate using the associated certificate
        // Reference: https://github.com/bugch3ck/SharpAltSecIds
        $string11 = "bugch3ck/SharpAltSecIds" nocase ascii wide
        // Description: Shadow Credentials via altSecurityIdentities - Enables attackers to add altSecurityIdentities entries to an account - linking it to an X.509 certificate for authentication. This allows them to impersonate the targeted account and authenticate using the associated certificate
        // Reference: https://github.com/bugch3ck/SharpAltSecIds
        $string12 = "d6304a65276af87fe87a4cddf75f571d1c73c601710fffebe9da17d762d521d2" nocase ascii wide
        // Description: Shadow Credentials via altSecurityIdentities - Enables attackers to add altSecurityIdentities entries to an account - linking it to an X.509 certificate for authentication. This allows them to impersonate the targeted account and authenticate using the associated certificate
        // Reference: https://github.com/bugch3ck/SharpAltSecIds
        $string13 = "SharpAltSecIds add" nocase ascii wide
        // Description: Shadow Credentials via altSecurityIdentities - Enables attackers to add altSecurityIdentities entries to an account - linking it to an X.509 certificate for authentication. This allows them to impersonate the targeted account and authenticate using the associated certificate
        // Reference: https://github.com/bugch3ck/SharpAltSecIds
        $string14 = "SharpAltSecIds by @bugch3ck" nocase ascii wide
        // Description: Shadow Credentials via altSecurityIdentities - Enables attackers to add altSecurityIdentities entries to an account - linking it to an X.509 certificate for authentication. This allows them to impersonate the targeted account and authenticate using the associated certificate
        // Reference: https://github.com/bugch3ck/SharpAltSecIds
        $string15 = "SharpAltSecIds command" nocase ascii wide
        // Description: Shadow Credentials via altSecurityIdentities - Enables attackers to add altSecurityIdentities entries to an account - linking it to an X.509 certificate for authentication. This allows them to impersonate the targeted account and authenticate using the associated certificate
        // Reference: https://github.com/bugch3ck/SharpAltSecIds
        $string16 = "SharpAltSecIds l /target:" nocase ascii wide
        // Description: Shadow Credentials via altSecurityIdentities - Enables attackers to add altSecurityIdentities entries to an account - linking it to an X.509 certificate for authentication. This allows them to impersonate the targeted account and authenticate using the associated certificate
        // Reference: https://github.com/bugch3ck/SharpAltSecIds
        $string17 = "SharpAltSecIds list" nocase ascii wide
        // Description: Shadow Credentials via altSecurityIdentities - Enables attackers to add altSecurityIdentities entries to an account - linking it to an X.509 certificate for authentication. This allows them to impersonate the targeted account and authenticate using the associated certificate
        // Reference: https://github.com/bugch3ck/SharpAltSecIds
        $string18 = "SharpAltSecIds r /target:" nocase ascii wide
        // Description: Shadow Credentials via altSecurityIdentities - Enables attackers to add altSecurityIdentities entries to an account - linking it to an X.509 certificate for authentication. This allows them to impersonate the targeted account and authenticate using the associated certificate
        // Reference: https://github.com/bugch3ck/SharpAltSecIds
        $string19 = "SharpAltSecIds remove" nocase ascii wide

    condition:
        any of them
}
