rule slip
{
    meta:
        description = "Detection patterns for the tool 'slip' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "slip"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string1 = /\s\-\-archive\-type\star\s\-\-mass\-find\s.{0,100}\s\-\-mass\-find\-mode\ssymlinks\sarchive/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string2 = /\s\-\-archive\-type\szip\s\-\-symlinks\s\\"\.\.\/etc\/hosts.{0,100}linkname\\"\sarchive\s\s/
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string3 = /\sslip\.py\s/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string4 = /\.\/slip\.py\s/
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string5 = /\/path_traversal_dict\.txt/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string6 = /\/slip\.git/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string7 = /\/slip\-main\.zip/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string8 = /\\path_traversal_dict\.txt/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string9 = /\\slip\.py\s/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string10 = /\\slip\-main\.zip/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string11 = "0xless/slip" nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string12 = /python3\sslip\.py/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string13 = /slip.{0,100}\s\-\-archive\-type\s.{0,100}\s\-\-compression\s.{0,100}\s\-\-paths\s.{0,100}\s\-\-file\-content\s/ nocase ascii wide
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
