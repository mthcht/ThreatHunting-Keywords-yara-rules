rule Argus
{
    meta:
        description = "Detection patterns for the tool 'Argus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Argus"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Information Gathering Toolkit
        // Reference: https://github.com/jasonxtn/Argus
        $string1 = "0d31ab15ca76d4169ac74d4f09b7d79b762758edad0c5f23032e3a53327045ec" nocase ascii wide
        // Description: Information Gathering Toolkit
        // Reference: https://github.com/jasonxtn/Argus
        $string2 = "16351c63e40c416d311b478ca4442d92fa7a74265ca58332b2a19b0568fb7479" nocase ascii wide
        // Description: Information Gathering Toolkit
        // Reference: https://github.com/jasonxtn/Argus
        $string3 = "1baa69530af844b454f505e1c21c1459d532efa7a0369cc78296121841355510" nocase ascii wide
        // Description: Information Gathering Toolkit
        // Reference: https://github.com/jasonxtn/Argus
        $string4 = "4fa756694752065bbcaf8bda18a23b6e25936e301dad50bde68ea4900592aeae" nocase ascii wide
        // Description: Information Gathering Toolkit
        // Reference: https://github.com/jasonxtn/Argus
        $string5 = "50008e82cf48a421aeda45c87b598339dfb18f7b336cdf9e4e2fb8677b377ea0" nocase ascii wide
        // Description: Information Gathering Toolkit
        // Reference: https://github.com/jasonxtn/Argus
        $string6 = "80096ca34a483165ffbef283b6afa771d8a4883a2d231604f7638a682b8a44f2" nocase ascii wide
        // Description: Information Gathering Toolkit
        // Reference: https://github.com/jasonxtn/Argus
        $string7 = "8c434e4c9fa572dd95d94193f9671e039fb8dd1705cf4c841aaa1969ce9dae2e" nocase ascii wide
        // Description: Information Gathering Toolkit
        // Reference: https://github.com/jasonxtn/Argus
        $string8 = "98e8bbdf74db34c8ebddf41e0f5574033df9d7c1390e37bcbe0466ce1705c6e4" nocase ascii wide
        // Description: Information Gathering Toolkit
        // Reference: https://github.com/jasonxtn/Argus
        $string9 = /ArgusCrawler\/1\.0/ nocase ascii wide
        // Description: Information Gathering Toolkit
        // Reference: https://github.com/jasonxtn/Argus
        $string10 = /ArgusDataLeakChecker\/1\.0/ nocase ascii wide
        // Description: Information Gathering Toolkit
        // Reference: https://github.com/jasonxtn/Argus
        $string11 = /Argus\-Scanner\/1\.0/ nocase ascii wide
        // Description: Information Gathering Toolkit
        // Reference: https://github.com/jasonxtn/Argus
        $string12 = "c90614a48df0d4005091daffbab57bbe716313999b39b27dfc1038748280b68f" nocase ascii wide
        // Description: Information Gathering Toolkit
        // Reference: https://github.com/jasonxtn/Argus
        $string13 = "e46766c1c80ea172d9c38d7d18674d29d9fd294014cf9d8e9557a6b2b3755a77" nocase ascii wide
        // Description: Information Gathering Toolkit
        // Reference: https://github.com/jasonxtn/Argus
        $string14 = "jasonxtn/Argus" nocase ascii wide
        // Description: Information Gathering Toolkit
        // Reference: https://github.com/jasonxtn/Argus
        $string15 = /Mozilla\/5\.0\s\(compatible\;\sArgusBot\/1\.0/ nocase ascii wide
        // Description: Information Gathering Toolkit
        // Reference: https://github.com/jasonxtn/Argus
        $string16 = /python\sargus\.py/ nocase ascii wide
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
