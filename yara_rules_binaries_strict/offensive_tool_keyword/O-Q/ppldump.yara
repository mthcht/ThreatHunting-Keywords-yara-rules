rule ppldump
{
    meta:
        description = "Detection patterns for the tool 'ppldump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ppldump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string1 = "6E8D2C12-255B-403C-9EF3-8A097D374DB2" nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string2 = /dllexploit\./ nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string3 = "FCE81BDA-ACAC-4892-969E-0414E765593B" nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string4 = /lsass\.exe.{0,100}\.dmp/ nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string5 = "PPLdump" nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string6 = /PPLdump\.exe/ nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string7 = /PPLdump64\.exe/ nocase ascii wide
        // Description: Dump the memory of a PPL with a userland exploit
        // Reference: https://github.com/itm4n/PPLdump
        $string8 = "PPLdumpDll" nocase ascii wide
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
