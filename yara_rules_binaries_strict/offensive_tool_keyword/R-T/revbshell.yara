rule revbshell
{
    meta:
        description = "Detection patterns for the tool 'revbshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "revbshell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ReVBShell - Reverse VBS Shell
        // Reference: https://github.com/bitsadmin/revbshell
        $string1 = /\/revbshell\.git/ nocase ascii wide
        // Description: ReVBShell - Reverse VBS Shell
        // Reference: https://github.com/bitsadmin/revbshell
        $string2 = /\\revbshell\-master/ nocase ascii wide
        // Description: ReVBShell - Reverse VBS Shell
        // Reference: https://github.com/bitsadmin/revbshell
        $string3 = "5f01ca453b976669370a3d5975837773107dd5522e8259dccda788993bb0da89" nocase ascii wide
        // Description: ReVBShell - Reverse VBS Shell
        // Reference: https://github.com/bitsadmin/revbshell
        $string4 = "bitsadmin/revbshell" nocase ascii wide
        // Description: ReVBShell - Reverse VBS Shell
        // Reference: https://github.com/bitsadmin/revbshell
        $string5 = "dcd8b443ee740b4ccd6674dd1e6b6cfccd9a202c282a67e06ce2f4aaa8a66d95" nocase ascii wide
        // Description: ReVBShell - Reverse VBS Shell
        // Reference: https://github.com/bitsadmin/revbshell
        $string6 = /pentest\-script\-master\.zip/ nocase ascii wide
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
