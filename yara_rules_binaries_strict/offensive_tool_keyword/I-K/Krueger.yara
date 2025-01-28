rule Krueger
{
    meta:
        description = "Detection patterns for the tool 'Krueger' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Krueger"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string1 = /\/Krueger\.exe/ nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string2 = /\/Krueger\.git/ nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string3 = /\@_logangoins\\n\@hullabrian/ nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string4 = /\\Krueger\.exe/ nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string5 = "022E5A85-D732-4C5D-8CAD-A367139068D8" nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string6 = "783c942169fb6fe2dd984470a470440dd10a1aec09a153759e8d78a95096a8e6" nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string7 = /ADMIN\$\\\\System32\\\\CodeIntegrity\\\\SiPolicy\.p7b/ nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string8 = /ADMIN\$\\System32\\CodeIntegrity\\SiPolicy\.p7b/ nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string9 = /C\$\\\\Windows\\\\System32\\\\CodeIntegrity\\\\SiPolicy\.p7b/ nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string10 = /C\$\\Windows\\System32\\CodeIntegrity\\SiPolicy\.p7b/ nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string11 = "d2a4f52a9923336f119a52e531bbb1e66f18322fd8efa9af1a64b94f4d36dc97" nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string12 = "d6bd37f7c1bcc7ea255d46c3f8f07e6fd754f566dd05682584def7c8ba0aebf9" nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string13 = /Krueger\.SiPolicy\.p7b/ nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string14 = "logangoins/Krueger" nocase ascii wide
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
