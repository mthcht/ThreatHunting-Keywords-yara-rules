rule Phant0m
{
    meta:
        description = "Detection patterns for the tool 'Phant0m' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Phant0m"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string1 = /\/Phant0m\.git/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string2 = "/phant0m-exe" nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string3 = /\\wmi_1\.dll/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string4 = /\\wmi_2\.dll/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string5 = "hlldz/Phant0m" nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string6 = /Invoke\-Phant0m\.ps1/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string7 = "Phant0m scm 1" nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string8 = "Phant0m scm 2" nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string9 = "Phant0m wmi" nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string10 = /phant0m\.cna/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string11 = /phant0m\-exe\./ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string12 = /Phant0m\-master\.zip/ nocase ascii wide
        // Description: Windows Event Log Killer
        // Reference: https://github.com/hlldz/Phant0m
        $string13 = "phant0m-rdll" nocase ascii wide
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
