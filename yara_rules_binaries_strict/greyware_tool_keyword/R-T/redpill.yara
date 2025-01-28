rule redpill
{
    meta:
        description = "Detection patterns for the tool 'redpill' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "redpill"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string1 = /\sGet\-AVStatus\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string2 = /\slist\-recycle\-bin\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string3 = /\sps2exe\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string4 = /\.ps1\s\-sysinfo\sEnum/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string5 = /\/ps2exe\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string6 = /\/vbs2exe\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string7 = /\\credentials\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string8 = /\\Get\-AVStatus\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string9 = /\\ksjjhav\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string10 = /\\list\-recycle\-bin\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string11 = /\\OutlookEmails\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string12 = /\\ps2exe\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string13 = /\\Screenshot\.exe\s/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string14 = /\\Screenshot\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string15 = /\\Temp\\clipboard\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string16 = /\\Temp\\dave\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string17 = /\\Temp\\fsdgss\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string18 = /\\vbs2exe\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string19 = /BATtoEXEconverter\.bat/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string20 = /identify_offensive_tools\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string21 = /Mitre\-T1202\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string22 = /Temp\\iprange\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string23 = /vbs2exe\.exe\s/ nocase ascii wide
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
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
