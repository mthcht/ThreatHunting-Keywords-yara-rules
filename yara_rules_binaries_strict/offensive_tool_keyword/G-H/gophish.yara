rule gophish
{
    meta:
        description = "Detection patterns for the tool 'gophish' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gophish"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string1 = " evilginx" nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string2 = "/evilginx" nocase ascii wide
        // Description: Open-Source Phishing Toolkit
        // Reference: https://github.com/gophish/gophish
        $string3 = /\/gophish\.db/ nocase ascii wide
        // Description: Open-Source Phishing Toolkit
        // Reference: https://github.com/gophish/gophish
        $string4 = "/gophish/" nocase ascii wide
        // Description: Gophish is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training.
        // Reference: https://github.com/gophish/gophish
        $string5 = "c121f7d62fa5ecd27c3aaae5737a3de8f2e4def0c182058b6dd824aa92351e9c" nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string6 = /evilfeed\.go/ nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string7 = "evilginx-linux" nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string8 = "evilgophish" nocase ascii wide
        // Description: Gophish is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training.
        // Reference: https://github.com/gophish/gophish
        $string9 = /gophish.{0,100}phish\.go/ nocase ascii wide
        // Description: Open-Source Phishing Toolkit
        // Reference: https://github.com/gophish/gophish
        $string10 = /gophish\.go/ nocase ascii wide
        // Description: Gophish is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training.
        // Reference: https://github.com/gophish/gophish
        $string11 = "gophish/gophish" nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string12 = "localhost:1337" nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string13 = "lures create " nocase ascii wide
        // Description: Open-Source Phishing Toolkit
        // Reference: https://github.com/gophish/gophish
        $string14 = /phish_test\.go/ nocase ascii wide
        // Description: Combination of evilginx2 and GoPhish
        // Reference: https://github.com/fin3ss3g0d/evilgophish
        $string15 = "phishlets " nocase ascii wide
        // Description: Hiding GoPhish from the boys in blue
        // Reference: https://github.com/puzzlepeaches/sneaky_gophish/
        $string16 = "sneaky_gophish" nocase ascii wide
        // Description: Gophish is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training.
        // Reference: https://github.com/gophish/gophish
        $string17 = "X-Gophish-Contact" nocase ascii wide
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
