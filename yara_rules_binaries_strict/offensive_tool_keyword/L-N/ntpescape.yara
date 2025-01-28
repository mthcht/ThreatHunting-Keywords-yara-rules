rule ntpescape
{
    meta:
        description = "Detection patterns for the tool 'ntpescape' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntpescape"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ntpescape is a tool that can stealthily (but slowly) exfiltrate data from a computer using the Network Time Protocol (NTP).
        // Reference: https://github.com/evallen/ntpescape
        $string1 = /\s\|\s\.\/send\s\-d\s.{0,100}\:123\s\-tM\s0\s\-tm\s0/
        // Description: ntpescape is a tool that can stealthily (but slowly) exfiltrate data from a computer using the Network Time Protocol (NTP).
        // Reference: https://github.com/evallen/ntpescape
        $string2 = /\.\/recv\s\-d\s\:50001/
        // Description: ntpescape is a tool that can stealthily (but slowly) exfiltrate data from a computer using the Network Time Protocol (NTP).
        // Reference: https://github.com/evallen/ntpescape
        $string3 = /\.\/send\s\-d\s.{0,100}\:123\s\-f\s/
        // Description: ntpescape is a tool that can stealthily (but slowly) exfiltrate data from a computer using the Network Time Protocol (NTP).
        // Reference: https://github.com/evallen/ntpescape
        $string4 = /\/ntpescape\.git/ nocase ascii wide
        // Description: ntpescape is a tool that can stealthily (but slowly) exfiltrate data from a computer using the Network Time Protocol (NTP).
        // Reference: https://github.com/evallen/ntpescape
        $string5 = "evallen/ntpescape" nocase ascii wide
        // Description: ntpescape is a tool that can stealthily (but slowly) exfiltrate data from a computer using the Network Time Protocol (NTP).
        // Reference: https://github.com/evallen/ntpescape
        $string6 = /ntpescape.{0,100}recv/ nocase ascii wide
        // Description: ntpescape is a tool that can stealthily (but slowly) exfiltrate data from a computer using the Network Time Protocol (NTP).
        // Reference: https://github.com/evallen/ntpescape
        $string7 = /ntpescape.{0,100}send/ nocase ascii wide
        // Description: ntpescape is a tool that can stealthily (but slowly) exfiltrate data from a computer using the Network Time Protocol (NTP).
        // Reference: https://github.com/evallen/ntpescape
        $string8 = /ntpescape\-master\./ nocase ascii wide
        // Description: ntpescape is a tool that can stealthily (but slowly) exfiltrate data from a computer using the Network Time Protocol (NTP).
        // Reference: https://github.com/evallen/ntpescape
        $string9 = /sudo\s\.\/recv\s\-f\s/
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
