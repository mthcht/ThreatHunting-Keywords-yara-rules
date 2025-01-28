rule Spyndicapped
{
    meta:
        description = "Detection patterns for the tool 'Spyndicapped' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Spyndicapped"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: COM ViewLogger - keylogger
        // Reference: https://github.com/CICADA8-Research/Spyndicapped
        $string1 = /\.exe\sspy\s\-\-pid\s/ nocase ascii wide
        // Description: COM ViewLogger - keylogger
        // Reference: https://github.com/CICADA8-Research/Spyndicapped
        $string2 = /\.exe\sspy\s\-\-window\s/ nocase ascii wide
        // Description: COM ViewLogger - keylogger
        // Reference: https://github.com/CICADA8-Research/Spyndicapped
        $string3 = /\/Spyndicapped\.exe/ nocase ascii wide
        // Description: COM ViewLogger - keylogger
        // Reference: https://github.com/CICADA8-Research/Spyndicapped
        $string4 = /\/Spyndicapped\.git/ nocase ascii wide
        // Description: COM ViewLogger - keylogger
        // Reference: https://github.com/CICADA8-Research/Spyndicapped
        $string5 = /\\Spyndicapped\.exe/ nocase ascii wide
        // Description: COM ViewLogger - keylogger
        // Reference: https://github.com/CICADA8-Research/Spyndicapped
        $string6 = /\\Spyndicapped_dev\\/ nocase ascii wide
        // Description: COM ViewLogger - keylogger
        // Reference: https://github.com/CICADA8-Research/Spyndicapped
        $string7 = /\\Spyndicapped\-main/ nocase ascii wide
        // Description: COM ViewLogger - keylogger
        // Reference: https://github.com/CICADA8-Research/Spyndicapped
        $string8 = "01ae8b32692998eefc9b050e189672ebbc6e356355fc5777957830fd8a067028" nocase ascii wide
        // Description: COM ViewLogger - keylogger
        // Reference: https://github.com/CICADA8-Research/Spyndicapped
        $string9 = "91ee16300f9af0ed8c9de365bcb3eeb8e1cf0d7b8b75ce8866ccaf8433fef75a" nocase ascii wide
        // Description: COM ViewLogger - keylogger
        // Reference: https://github.com/CICADA8-Research/Spyndicapped
        $string10 = "cd9c66c8-8fcb-4d43-975b-a9c8d02ad090" nocase ascii wide
        // Description: COM ViewLogger - keylogger
        // Reference: https://github.com/CICADA8-Research/Spyndicapped
        $string11 = "CICADA8-Research/Spyndicapped" nocase ascii wide
        // Description: COM ViewLogger - keylogger
        // Reference: https://github.com/CICADA8-Research/Spyndicapped
        $string12 = "Spyndicapped spy " nocase ascii wide
        // Description: COM ViewLogger - keylogger
        // Reference: https://github.com/CICADA8-Research/Spyndicapped
        $string13 = "Started spying using MyAutomationEventHandler" nocase ascii wide
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
