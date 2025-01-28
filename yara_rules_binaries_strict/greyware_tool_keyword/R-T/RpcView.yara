rule RpcView
{
    meta:
        description = "Detection patterns for the tool 'RpcView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RpcView"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: RpcView is a free tool to explore and decompile Microsoft RPC interfaces
        // Reference: https://github.com/silverf0x/RpcView
        $string1 = /\\RpcView\.exe/ nocase ascii wide
        // Description: RpcView is a free tool to explore and decompile Microsoft RPC interfaces
        // Reference: https://github.com/silverf0x/RpcView
        $string2 = /\\RpcView64\.7z/ nocase ascii wide
        // Description: RpcView is a free tool to explore and decompile Microsoft RPC interfaces
        // Reference: https://github.com/silverf0x/RpcView
        $string3 = "0d2d07010e3ad3219d37b9a10a04abf50bd84c6c429b96aab5aad70f31c42efe" nocase ascii wide
        // Description: RpcView is a free tool to explore and decompile Microsoft RPC interfaces
        // Reference: https://github.com/silverf0x/RpcView
        $string4 = "a1d89c9d81a2e9c7558e8f0c91ec8652d40af94726f3125f9fe31206adb528de" nocase ascii wide
        // Description: RpcView is a free tool to explore and decompile Microsoft RPC interfaces
        // Reference: https://github.com/silverf0x/RpcView
        $string5 = "silverf0x/RpcView" nocase ascii wide
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
