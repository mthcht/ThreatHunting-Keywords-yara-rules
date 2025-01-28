rule Spartacus
{
    meta:
        description = "Detection patterns for the tool 'Spartacus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Spartacus"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string1 = /\s\-\-action\sexports\s\-\-dll\sC\:\\Windows\\System32\\amsi\.dll/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string2 = /\s\-\-dll\s.{0,100}\s\-\-only\s.{0,100}AmsiScanBuffer.{0,100}AmsiScanString/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string3 = /\s\-\-dll\sC\:\\Windows\\System32\\version\.dll.{0,100}\-\-dll\sC\:\\Windows\\System32\\userenv\.dll/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string4 = /\s\-\-mode\sproxy\s\-\-ghidra\s.{0,100}\-\-dll\s/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string5 = /\\tmp\\dll\-collection/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string6 = "Accenture/Spartacus" nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string7 = /Assets\/solution\/dllmain\.cpp/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string8 = /Data\\VulnerableCOM\.csv/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string9 = /exports\s\-\-dll\s.{0,100}\.dll\s\-\-prototypes\s\.\/Assets\/prototypes\.csv/
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string10 = /help\\dll\.txt/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string11 = "--mode com --acl --csv " nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string12 = "--mode com --procmon " nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string13 = "--mode dll --existing --pml " nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string14 = "--mode dll --procmon " nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string15 = /\-\-mode\sproxy\s\-\-action\sprototypes\s\-\-path\s.{0,100}prototypes\.csv/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string16 = /\-\-mode\sproxy\s\-\-dll\s.{0,100}\.dll.{0,100}\-\-external\-resources/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string17 = /\-\-mode\sproxy\s\-\-ghidra\s.{0,100}\-\-dll\s/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string18 = /Spartacus\.exe\s\-\-mode\sproxy/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string19 = /Spartacus\-main\.zip/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string20 = /spartacus\-proxy\-.{0,100}\.log/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string21 = /Spartacus\-v2\..{0,100}\-x64\.zip/ nocase ascii wide
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
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
