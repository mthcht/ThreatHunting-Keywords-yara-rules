rule SingleDose
{
    meta:
        description = "Detection patterns for the tool 'SingleDose' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SingleDose"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SingleDose is a framework to build shellcode load/process injection techniques
        // Reference: https://github.com/Wra7h/SingleDose
        $string1 = /\/SingleDose\.git/ nocase ascii wide
        // Description: SingleDose is a framework to build shellcode load/process injection techniques
        // Reference: https://github.com/Wra7h/SingleDose
        $string2 = /\\Payloads\\.{0,100}\.bin/ nocase ascii wide
        // Description: SingleDose is a framework to build shellcode load/process injection techniques
        // Reference: https://github.com/Wra7h/SingleDose
        $string3 = /\\PoisonTendy\\Invokes\\/ nocase ascii wide
        // Description: SingleDose is a framework to build shellcode load/process injection techniques
        // Reference: https://github.com/Wra7h/SingleDose
        $string4 = /\\SingleDose\.csproj/ nocase ascii wide
        // Description: SingleDose is a framework to build shellcode load/process injection techniques
        // Reference: https://github.com/Wra7h/SingleDose
        $string5 = /\\SingleDose\.exe/ nocase ascii wide
        // Description: SingleDose is a framework to build shellcode load/process injection techniques
        // Reference: https://github.com/Wra7h/SingleDose
        $string6 = /\\SingleDose\.sln/ nocase ascii wide
        // Description: SingleDose is a framework to build shellcode load/process injection techniques
        // Reference: https://github.com/Wra7h/SingleDose
        $string7 = /\\SingleDose\-main\.zip/ nocase ascii wide
        // Description: SingleDose is a framework to build shellcode load/process injection techniques
        // Reference: https://github.com/Wra7h/SingleDose
        $string8 = "4D7AEF0B-5AA6-4AE5-971E-7141AA1FDAFC" nocase ascii wide
        // Description: SingleDose is a framework to build shellcode load/process injection techniques
        // Reference: https://github.com/Wra7h/SingleDose
        $string9 = "5FAC3991-D4FD-4227-B73D-BEE34EB89987" nocase ascii wide
        // Description: SingleDose is a framework to build shellcode load/process injection techniques
        // Reference: https://github.com/Wra7h/SingleDose
        $string10 = "C0E67E76-1C78-4152-9F79-FA27B4F7CCCA" nocase ascii wide
        // Description: SingleDose is a framework to build shellcode load/process injection techniques
        // Reference: https://github.com/Wra7h/SingleDose
        $string11 = /PoisonTendy\.dll/ nocase ascii wide
        // Description: SingleDose is a framework to build shellcode load/process injection techniques
        // Reference: https://github.com/Wra7h/SingleDose
        $string12 = "Wra7h/SingleDose" nocase ascii wide
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
