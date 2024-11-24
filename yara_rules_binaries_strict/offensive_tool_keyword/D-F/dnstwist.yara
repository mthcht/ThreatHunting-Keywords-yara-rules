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
        $string15 = /Mozilla\/5\.0\s\(.{0,100}\-bit\)\sdnstwist/ nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string16 = "randomalice1986@" nocase ascii wide
        // Description: See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters. phishing attacks. fraud. and brand impersonation. Useful as an additional source of targeted threat intelligence.
        // Reference: https://github.com/elceef/dnstwist
        $string17 = "randombob1986@" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
