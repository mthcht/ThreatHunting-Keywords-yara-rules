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
        $string1 = /.{0,1000}\s\-\-fuzzers\saddition.{0,1000}/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string2 = /.{0,1000}\s\-\-fuzzers\sbitsquatting.{0,1000}/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string3 = /.{0,1000}\s\-\-fuzzers\scyrillic.{0,1000}/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string4 = /.{0,1000}\s\-\-fuzzers\sdictionary.{0,1000}/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string5 = /.{0,1000}\s\-\-fuzzers\shomoglyph.{0,1000}/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string6 = /.{0,1000}\s\-\-fuzzers\shyphenation.{0,1000}/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string7 = /.{0,1000}\s\-\-fuzzers\sinsertion.{0,1000}/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string8 = /.{0,1000}\s\-\-fuzzers\somission.{0,1000}/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string9 = /.{0,1000}\s\-\-fuzzers\srepetition.{0,1000}/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string10 = /.{0,1000}\s\-\-fuzzers\sreplacement.{0,1000}/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string11 = /.{0,1000}\s\-\-fuzzers\ssubdomain.{0,1000}/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string12 = /.{0,1000}\s\-\-fuzzers\stransposition.{0,1000}/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string13 = /.{0,1000}\s\-\-fuzzers\svowel\-swap.{0,1000}/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string14 = /.{0,1000}dnstwist.{0,1000}/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string15 = /.{0,1000}Mozilla\/5\.0\s\(.{0,1000}\-bit\)\sdnstwist.{0,1000}/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string16 = /.{0,1000}randomalice1986\@.{0,1000}/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string17 = /.{0,1000}randombob1986\@.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
