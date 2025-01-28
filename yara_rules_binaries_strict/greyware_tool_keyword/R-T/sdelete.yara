rule sdelete
{
    meta:
        description = "Detection patterns for the tool 'sdelete' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sdelete"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: SDelete is an application that securely deletes data in a way that makes it unrecoverable.- abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string1 = /\/sdelete\.exe/ nocase ascii wide
        // Description: SDelete is an application that securely deletes data in a way that makes it unrecoverable.- abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string2 = /\/SDelete\.zip/ nocase ascii wide
        // Description: SDelete is an application that securely deletes data in a way that makes it unrecoverable.- abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string3 = /\/sdelete64\.exe/ nocase ascii wide
        // Description: delete one or more files and/or directories, or to cleanse the free space on a logical disk - abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string4 = /\/sdelete64a\.exe/ nocase ascii wide
        // Description: delete one or more files and/or directories, or to cleanse the free space on a logical disk - abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string5 = /\\sdelete\.exe/ nocase ascii wide
        // Description: delete one or more files and/or directories, or to cleanse the free space on a logical disk - abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string6 = /\\SDelete\.zip/ nocase ascii wide
        // Description: delete one or more files and/or directories, or to cleanse the free space on a logical disk - abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string7 = /\\sdelete64\.exe/ nocase ascii wide
        // Description: delete one or more files and/or directories, or to cleanse the free space on a logical disk - abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string8 = /\\sdelete64a\.exe/ nocase ascii wide
        // Description: delete one or more files and/or directories, or to cleanse the free space on a logical disk - abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string9 = /\\Software\\Sysinternals\\Sdelete/ nocase ascii wide
        // Description: delete one or more files and/or directories, or to cleanse the free space on a logical disk - abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string10 = /\>sdelete\.exe\</ nocase ascii wide
        // Description: delete one or more files and/or directories, or to cleanse the free space on a logical disk - abused by attackers
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
        $string11 = ">sysinternals sdelete<" nocase ascii wide
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
