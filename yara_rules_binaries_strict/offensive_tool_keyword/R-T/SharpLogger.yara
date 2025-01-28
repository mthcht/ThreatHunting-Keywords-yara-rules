rule SharpLogger
{
    meta:
        description = "Detection patterns for the tool 'SharpLogger' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpLogger"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Keylogger written in C#
        // Reference: https://github.com/djhohnstein/SharpLogger
        $string1 = /\/SharpLogger\.exe/ nocase ascii wide
        // Description: Keylogger written in C#
        // Reference: https://github.com/djhohnstein/SharpLogger
        $string2 = /\\SharpLogger\.exe/ nocase ascii wide
        // Description: Keylogger written in C#
        // Reference: https://github.com/djhohnstein/SharpLogger
        $string3 = "36E00152-E073-4DA8-AA0C-375B6DD680C4" nocase ascii wide
        // Description: Keylogger written in C#
        // Reference: https://github.com/djhohnstein/SharpLogger
        $string4 = "4dbd32931bc77778850c20282a9e3adebd4d23b7ef4b0635380b520c432b48d9" nocase ascii wide
        // Description: Keylogger written in C#
        // Reference: https://github.com/djhohnstein/SharpLogger
        $string5 = "9d7bfb3aeba4145896ece197216c4269deee6cce93eed3ffafe442ed05aeb4c4" nocase ascii wide
        // Description: Keylogger written in C#
        // Reference: https://github.com/djhohnstein/SharpLogger
        $string6 = "djhohnstein/SharpLogger" nocase ascii wide
        // Description: Keylogger written in C#
        // Reference: https://github.com/djhohnstein/SharpLogger
        $string7 = /Keylogger\.csproj/ nocase ascii wide
        // Description: Keylogger written in C#
        // Reference: https://github.com/djhohnstein/SharpLogger
        $string8 = /Keylogger\.exe/ nocase ascii wide
        // Description: Keylogger written in C#
        // Reference: https://github.com/djhohnstein/SharpLogger
        $string9 = "namespace Keylogger" nocase ascii wide
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
