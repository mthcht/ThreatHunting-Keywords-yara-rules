rule SharpMiniDump
{
    meta:
        description = "Detection patterns for the tool 'SharpMiniDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpMiniDump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Create a minidump of the LSASS process from memory
        // Reference: https://github.com/b4rtik/SharpMiniDump
        $string1 = /\/SharpMiniDump\.git/ nocase ascii wide
        // Description: Create a minidump of the LSASS process from memory
        // Reference: https://github.com/b4rtik/SharpMiniDump
        $string2 = /\\SharpMiniDump\-master/ nocase ascii wide
        // Description: Create a minidump of the LSASS process from memory
        // Reference: https://github.com/b4rtik/SharpMiniDump
        $string3 = /\\Temp\\dumpert\.dmp/ nocase ascii wide
        // Description: Create a minidump of the LSASS process from memory
        // Reference: https://github.com/b4rtik/SharpMiniDump
        $string4 = ">SharpMiniDump<" nocase ascii wide
        // Description: Create a minidump of the LSASS process from memory
        // Reference: https://github.com/b4rtik/SharpMiniDump
        $string5 = "34cfee78a17d917fabf8d9a2b48fb55f8231c0b24a5f4197615d140d18eb9b2d" nocase ascii wide
        // Description: Create a minidump of the LSASS process from memory
        // Reference: https://github.com/b4rtik/SharpMiniDump
        $string6 = "40a2c9d397f398d5faa631d6c6070174807e39962a22be143e35b7497b5c6bd7" nocase ascii wide
        // Description: Create a minidump of the LSASS process from memory
        // Reference: https://github.com/b4rtik/SharpMiniDump
        $string7 = "6FFCCF81-6C3C-4D3F-B15F-35A86D0B497F" nocase ascii wide
        // Description: Create a minidump of the LSASS process from memory
        // Reference: https://github.com/b4rtik/SharpMiniDump
        $string8 = "b4rtik/SharpMiniDump" nocase ascii wide
        // Description: Create a minidump of the LSASS process from memory
        // Reference: https://github.com/b4rtik/SharpMiniDump
        $string9 = "f988bd7635bc12561e00eeb4aff027bd8014dc9b13600c8e8fb597ac9de5c3cf" nocase ascii wide
        // Description: Create a minidump of the LSASS process from memory
        // Reference: https://github.com/b4rtik/SharpMiniDump
        $string10 = /SharpMiniDump\.exe/ nocase ascii wide
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
