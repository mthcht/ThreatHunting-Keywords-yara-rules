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
        $string1 = /\s\-\-fuzzers\saddition/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string2 = /\s\-\-fuzzers\sbitsquatting/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string3 = /\s\-\-fuzzers\scyrillic/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string4 = /\s\-\-fuzzers\sdictionary/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string5 = /\s\-\-fuzzers\shomoglyph/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string6 = /\s\-\-fuzzers\shyphenation/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string7 = /\s\-\-fuzzers\sinsertion/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string8 = /\s\-\-fuzzers\somission/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string9 = /\s\-\-fuzzers\srepetition/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string10 = /\s\-\-fuzzers\sreplacement/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string11 = /\s\-\-fuzzers\ssubdomain/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string12 = /\s\-\-fuzzers\stransposition/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string13 = /\s\-\-fuzzers\svowel\-swap/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string14 = /dnstwist/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string15 = /Mozilla\/5\.0\s\(.{0,1000}\-bit\)\sdnstwist/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string16 = /randomalice1986\@/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string17 = /randombob1986\@/ nocase ascii wide

    condition:
        any of them
}
