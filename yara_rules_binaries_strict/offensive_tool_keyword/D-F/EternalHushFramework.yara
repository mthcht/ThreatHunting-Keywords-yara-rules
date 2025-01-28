rule EternalHushFramework
{
    meta:
        description = "Detection patterns for the tool 'EternalHushFramework' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EternalHushFramework"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string1 = " EternalHushCore " nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string2 = /\/EternalHushCore\.dll/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string3 = /\/EternalHushFramework\.git/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string4 = /\\EternalHushCore\.dll/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string5 = /\\EternalHushCore\\/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string6 = "APT64/EternalHushFramework" nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string7 = /EternalHushFramework\-.{0,100}\-SNAPSHOT\.jar/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string8 = "EternalHushFramework-main" nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string9 = /EternalHushMain\.java/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string10 = /EternalHushWindow\.java/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string11 = "import _eternalhush" nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string12 = /import\seternalhush\./ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string13 = /SELECT\s.{0,100}\sFROM\sEvilSignature/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string14 = "W2F1dG9ydW5dDQpzaGVsbGV4ZWN1dGU9eTMyNHNlZHguZXhlDQppY29uPSVTeXN0ZW1Sb290JVxzeXN0ZW0zMlxTSEVMTDMyLmRsbCw0DQphY3Rpb249T3BlbiBmb2xkZXIgdG8gdmlldyBmaWxlcw0Kc2hlbGxcZGVmYXVsdD1PcGVuDQpzaGVsbFxkZWZhdWx0XGNvbW1hbmQ9eTMyNHNlZHguZXhlDQpzaGVsbD1kZWZhdWx0" nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string15 = /X32_ClSp_Tcp_Exe\.exe/ nocase ascii wide
        // Description: EternalHush Framework is a new open source project that is an advanced C&C framework. Designed specifically for Windows operating systems
        // Reference: https://github.com/APT64/EternalHushFramework
        $string16 = /X64_ClSp_Tcp_Exe\.exe/ nocase ascii wide
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
