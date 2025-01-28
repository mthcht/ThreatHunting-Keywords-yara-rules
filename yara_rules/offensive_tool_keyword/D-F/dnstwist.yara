rule dnstwist
{
    meta:
        description = "Detection patterns for the tool 'dnstwist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnstwist"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string1 = " --fuzzers addition" nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string2 = " --fuzzers bitsquatting" nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string3 = " --fuzzers cyrillic" nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string4 = " --fuzzers dictionary" nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string5 = " --fuzzers homoglyph" nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string6 = " --fuzzers hyphenation" nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string7 = " --fuzzers insertion" nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string8 = " --fuzzers omission" nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string9 = " --fuzzers repetition" nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string10 = " --fuzzers replacement" nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string11 = " --fuzzers subdomain" nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string12 = " --fuzzers transposition" nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string13 = " --fuzzers vowel-swap" nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string14 = "dnstwist" nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string15 = /Mozilla\/5\.0\s\(.{0,1000}\-bit\)\sdnstwist/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string16 = "randomalice1986@" nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string17 = "randombob1986@" nocase ascii wide

    condition:
        any of them
}
