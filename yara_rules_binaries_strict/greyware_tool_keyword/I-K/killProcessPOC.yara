rule killProcessPOC
{
    meta:
        description = "Detection patterns for the tool 'killProcessPOC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "killProcessPOC"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string1 = /\/killProcessPOC\.git/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string2 = /\\\\\\\\\.\\\\aswSP_ArPot0/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string3 = /\\\\\\\\\.\\\\aswSP_ArPot1/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string4 = /\\\\\\\\\.\\\\aswSP_ArPot2/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string5 = /\\\\\\\\\.\\\\aswSP_ArPot3/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string6 = /\\\\\\\\\.\\\\aswSP_Avar/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string7 = /\\killProcessPOC/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string8 = "55ab03a0f7e3ce2c13664db76e5e0b6768cb66d88971b6bc6caf577831a77a23" nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string9 = /sc\.exe\screate\saswSP_ArPot1/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string10 = /sc\.exe\screate\saswSP_ArPot2/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string11 = /sc\.exe\screate\saswSP_ArPot3/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string12 = /sc\.exe\screate\saswSP_ArPots/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string13 = /sc\.exe\sstart\saswSP_ArPot/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string14 = "timwhitez/killProcessPOC" nocase ascii wide
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
