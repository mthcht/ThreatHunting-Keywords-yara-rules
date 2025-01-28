rule OpenChromeDumps
{
    meta:
        description = "Detection patterns for the tool 'OpenChromeDumps' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OpenChromeDumps"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: OpenChrome Dump used with GrabChrome for credential access
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string1 = /\\openchromedumps\.exe/ nocase ascii wide
        // Description: OpenChrome Dump used with GrabChrome for credential access
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string2 = /\\openChromeDumps\.pdb/ nocase ascii wide
        // Description: OpenChrome Dump used with GrabChrome for credential access
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string3 = "0b9219328ebf065db9b26c9a189d72c7d0d9c39eb35e9fd2a5fefa54a7f853e4" nocase ascii wide
        // Description: OpenChrome Dump used with GrabChrome for credential access
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string4 = "1c543ea5c50ef8b0b42f835970fa5f553c2ae5c308d2692b51fb476173653cb3" nocase ascii wide
        // Description: OpenChrome Dump used with GrabChrome for credential access
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string5 = "99e25d4179b7a0419d07f671ab86f25a86582e256e0862fc431eb7f93cfb3ced" nocase ascii wide
        // Description: OpenChrome Dump used with GrabChrome for credential access
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string6 = /openChromeDumpsHTML\.exe/ nocase ascii wide
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
