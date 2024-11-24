rule RedPersist
{
    meta:
        description = "Detection patterns for the tool 'RedPersist' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RedPersist"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string1 = /\.exe\s\-\-eventviewer\s.{0,100}\.exe/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string2 = /\.exe\s\-\-pwsh\s.{0,100}\.ps1\s.{0,100}\.exe/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string3 = /\.exe\s\-\-schedule\s.{0,100}\s.{0,100}\.exe/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string4 = /\.exe\s\-\-screensaver\s.{0,100}\:\\.{0,100}\.exe/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string5 = /\.exe\s\-\-startup\s.{0,100}\:\\.{0,100}\.exe/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string6 = /\.exe\s\-\-winlogon\s.{0,100}\s.{0,100}\:\\.{0,100}\.exe/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string7 = /\.exe\s\-\-wmi\s.{0,100}\:\\.{0,100}\.exe/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string8 = /\/RedPersist\.exe/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string9 = /\/RedPersist\.git/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string10 = /\\RedPersist\.exe/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string11 = /\\RedPersist\.pdb/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string12 = /\\RedPersist\.sln/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string13 = /\\RedPersist\-main\\/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string14 = /\]\sEventviewer\sPersistence\screated/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string15 = /\]\sExtension\sHijacking\sPersistence\screated/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string16 = /\]\sPowershell\sPersistence\screated/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string17 = /\]\sScreensaver\sPersistence\screated/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string18 = /\]\sStartup\sPersistence\screated/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string19 = /\]\sUserInitMprLogonScript\sPersistence\screated/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string20 = "BD745A5E-A1E9-4FDD-A15B-E9F303A625AE" nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string21 = "bd745a5e-a1e9-4fdd-a15b-e9f303a625ae" nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string22 = "Hello From sadsad Team" nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string23 = "mertdas/RedPersist" nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string24 = /namespace\sRedPersist\.Persist/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string25 = /Persist\\autorun\.cs/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string26 = /Persist\\eventviewer\.cs/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string27 = /Persist\\powershell\.cs/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string28 = /Persist\\screensaver\.cs/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string29 = /Persist\\startup\.cs/ nocase ascii wide
        // Description: RedPersist is a Windows Persistence tool written in C#
        // Reference: https://github.com/mertdas/RedPersist
        $string30 = /Persist\\winlogon\.cs/ nocase ascii wide
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
