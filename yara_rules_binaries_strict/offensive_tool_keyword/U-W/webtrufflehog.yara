rule webtrufflehog
{
    meta:
        description = "Detection patterns for the tool 'webtrufflehog' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "webtrufflehog"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string1 = /\/com\.webtrufflehog\.json/ nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string2 = /\/webtrufflehog\.git/ nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string3 = /\/webtrufflehog\.log/ nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string4 = /\\webtrufflehog\.log/ nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string5 = /\\webtrufflehog\-main/ nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string6 = "450746e51e6f1369e7e73c5e2122d0ca81153d3a4c7bcec3d66266b15ee547f7" nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string7 = "52b6c057a9e0af822cbe129053d2c2d3541bf6e9ef162432fae60fdbd7a2d0f0" nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string8 = "85239f4abe215e87a147a6f63e8a281c2c3a687dcc45d430042c1e897de36696" nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string9 = "922d41ca55d3fa150f1c8fdc1f030e2acf6c24fcbd0ce1cd1021aeffe29bf24c" nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string10 = "akoofbljmjeodfmdpjndmmnifglppjdi" nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string11 = "c3l3si4n/webtrufflehog" nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string12 = "d62a0e8ea863d3812dcbf3927534db6b2a82223f2bfd2c374c7263be98b855f1" nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string13 = /scan_with_trufflehog\(/ nocase ascii wide
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
