rule SharpIncrease
{
    meta:
        description = "Detection patterns for the tool 'SharpIncrease' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpIncrease"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string1 = /\/SharpIncrease\.exe/ nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string2 = /\/SharpIncrease\.git/ nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string3 = /\\SharpIncrease\.exe/ nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string4 = /\\SharpIncrease\.sln/ nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string5 = ">SharpIncrease<" nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string6 = "77849d97ebdb4c100d7195a3904fb6b829219bb9f8df46dd81151550546da532" nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string7 = "84075d23f3358b16e1f68b1eb56d34d34e88da9b29d504d36b5de2522cf6c23f" nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string8 = "B19E7FDE-C2CB-4C0A-9C5E-DFC73ADDB5C0" nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string9 = "f36ae1ef8fa544943bbd65f44d53fd994b42c91042e133c69019c66e73b20278" nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string10 = "mertdas/SharpIncrease" nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string11 = /SharpIncrease\.exe\s\-D\s/ nocase ascii wide
        // Description: binary padding to add junk data and change the on-disk representation of a file
        // Reference: https://github.com/mertdas/SharpIncrease
        $string12 = /SharpIncrease\-main\.zip/ nocase ascii wide
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
