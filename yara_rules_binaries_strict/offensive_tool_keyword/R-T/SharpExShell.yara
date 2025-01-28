rule SharpExShell
{
    meta:
        description = "Detection patterns for the tool 'SharpExShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpExShell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string1 = /\/SharpExcelDCom\.exe/ nocase ascii wide
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string2 = /\/SharpExShell\.exe/ nocase ascii wide
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string3 = /\/SharpExShell\.git/ nocase ascii wide
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string4 = /\\SharpExcelDCom\.exe/ nocase ascii wide
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string5 = /\\SharpExShell\.exe/ nocase ascii wide
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string6 = /\\SharpExShell\.sln/ nocase ascii wide
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string7 = "13C84182-2F5F-4EE8-A37A-4483E7E57154" nocase ascii wide
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string8 = "37618f36a162e667eb98cb36bc1568524f87efc7cc12ef6d0ea4ef2f225c799d" nocase ascii wide
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string9 = "4848f468fc1f6b5c933d83be4e9295cf6af8eb74b789fdf0a6f116c7444808b2" nocase ascii wide
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string10 = "a63bf8aa62471b0cb62919e6e387482895a8027d5f763aba5f76572a595d7a31" nocase ascii wide
        // Description: SharpExShell automates the DCOM lateral movment technique which abuses ActivateMicrosoftApp method of Excel application
        // Reference: https://github.com/grayhatkiller/SharpExShell
        $string11 = "grayhatkiller/SharpExShell" nocase ascii wide
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
