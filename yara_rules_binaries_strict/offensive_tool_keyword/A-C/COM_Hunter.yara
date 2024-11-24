rule COM_Hunter
{
    meta:
        description = "Detection patterns for the tool 'COM-Hunter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "COM-Hunter"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string1 = /\sPersist\sGeneral\s.{0,100}\.dll/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string2 = /\sPersist\sTasksch\s.{0,100}\.dll/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string3 = /\sPersist\sTreatAs\s.{0,100}\.dll/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string4 = /\.exe\sSearch\sFind\-Persist/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string5 = /\/COM\-Hunter\.csproj/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string6 = /\/COM\-Hunter\.exe/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string7 = /\/COM\-Hunter\.git/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string8 = /\/COM\-Hunter\.sln/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string9 = /\\COM\-Hunter\.csproj/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string10 = /\\COM\-Hunter\.exe/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string11 = /\\COM\-Hunter\.sln/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string12 = "09323E4D-BE0F-452A-9CA8-B07D2CFA9804" nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string13 = /COM\-Hunter_v.{0,100}\.zip/ nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string14 = "COM-Hunter-main" nocase ascii wide
        // Description: COM-hunter is a COM Hijacking persistnce tool written in C#
        // Reference: https://github.com/nickvourd/COM-Hunter
        $string15 = "nickvourd/COM-Hunter" nocase ascii wide
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
