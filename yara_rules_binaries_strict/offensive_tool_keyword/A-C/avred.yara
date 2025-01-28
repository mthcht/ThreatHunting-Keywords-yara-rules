rule avred
{
    meta:
        description = "Detection patterns for the tool 'avred' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "avred"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string1 = /\savred\.py\s/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string2 = /\savredweb\.py\s/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string3 = /\.py\s\-\-file\s.{0,100}\.ps1\s\-\-server\samsi/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string4 = /\.py\s\-\-server\samsi\s\-\-file\s.{0,100}\.exe/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string5 = /\/avred\.git/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string6 = /\/avred\.py/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string7 = /\/avredweb\.py\s/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string8 = "/dobin/avred" nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string9 = /\\avred\.py/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string10 = /\\avredweb\.py\s/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string11 = /avred\-main\.zip/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string12 = /https\:\/\/avred\.r00ted\.ch\/upload/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string13 = /podman\srun\s.{0,100}\s\-\-name\savred\s\-d\savred/ nocase ascii wide
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
