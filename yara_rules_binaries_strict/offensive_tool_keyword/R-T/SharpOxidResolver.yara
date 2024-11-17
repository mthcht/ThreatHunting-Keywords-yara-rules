rule SharpOxidResolver
{
    meta:
        description = "Detection patterns for the tool 'SharpOxidResolver' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpOxidResolver"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string1 = /\/SharpOxidResolver\.git/ nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string2 = /\/SharpOxidResolver\/releases\/download\// nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string3 = /\\OxidResolver\.exe/ nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string4 = /52BBA3C2\-A74E\-4096\-B65F\-B88C38F92120/ nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string5 = /6f2b8cefcfe918b0e6ae0449e03ee2bc0cfe9224dff57271478ebb5110965ffd/ nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string6 = /bb94573eaa965f3371451dcfbde19645354cfd7a8d18f2022d2497d182e72754/ nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string7 = /f9bfe5ec7093e75a2baeb578e87084aa65cd5bc5bd4ffaa4c3d4f9e051cd6a00/ nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string8 = /IOXIDResolver\.py/ nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string9 = /Nxy8P0NrG2AqvW5n5IAlaEbxDvev9hTfHiktFAhCDboW5oqsPSFu7\/xd6lTi43sXD4yfw\=/ nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string10 = /OxidResolver\.exe/ nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string11 = /S3cur3Th1sSh1t\/SharpOxidResolver/ nocase ascii wide
        // Description: search the current domain for computers and get bindings for all of them
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpOxidResolver
        $string12 = /XjKVGK8ONDO9zVYwyGZBcz0pRjnm9eDj6vPpYOZqeAgr1n7aqBNgZPZolYoc\=/ nocase ascii wide
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
