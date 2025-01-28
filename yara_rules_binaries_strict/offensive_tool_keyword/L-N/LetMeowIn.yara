rule LetMeowIn
{
    meta:
        description = "Detection patterns for the tool 'LetMeowIn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LetMeowIn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string1 = /\srestoresig\.py/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string2 = /\/LetMeowIn\.git/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string3 = /\/restoresig\.py/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string4 = /\\restoresig\.py/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string5 = "0x4d, 0x44, 0x4d, 0x50, 0x93, 0xa7, 0x00, 0x00" nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string6 = "736b362973af7010de9bf1cea58547a17a236e81a2084c344cf06a1b184698bb" nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string7 = /C\:\\\\temp\\\\debug\.dmp/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string8 = "Creating offline copies of the LSASS process to perform memory dumps on" nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string9 = "da5d6eca1efe3219fa8102a0afbf9823dc8b2c00dd53af20960ed29bca1b2cef" nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string10 = /Don\'t\sbe\sevil\swith\sthis\.\sI\screated\sthis\stool\sto\slearn/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string11 = /\'l\'\,\s\'s\'\,\s\'a\'\,\s\'s\'\,\s\'s\'\,\s\'\.\'\,\s\'e\'\,\s\'x\'\,\s\'e\'/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string12 = /L\'D\'\,\sL\'b\'\,\sL\'g\'\,\sL\'h\'\,\sL\'e\'\,\sL\'l\'\,\sL\'p\'\,\sL\'\.\'\,\sL\'d\'\,\sL\'l\'\,\sL\'l\'\,\sL\'\\0\'/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string13 = /LetMeowIn\.exe/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string14 = /LetMeowIn\-main\.zip/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string15 = /L\'n\'\,\sL\'t\'\,\sL\'d\'\,\sL\'l\'\,\sL\'l\'\,\sL\'\.\'\,\sL\'d\'\,\sL\'l\'\,\sL\'l\'\,\sL\'\\0\'/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string16 = "L'S', L'e', L'D', L'e', L'b', L'u', L'g', L'P', L'r', L'i', L'v', L'i', L'l', L'e', L'g', L'e'" nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string17 = "'M', 'i', 'n', 'i', 'D', 'u', 'm', 'p', 'W', 'r', 'i', 't', 'e', 'D', 'u', 'm', 'p'" nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string18 = "Meowmycks/LetMeowIn" nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string19 = /Try\sopening\sit\swith\sMimikatz\snow\s\:\)/ nocase ascii wide
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
