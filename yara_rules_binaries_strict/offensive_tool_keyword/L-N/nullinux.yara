rule nullinux
{
    meta:
        description = "Detection patterns for the tool 'nullinux' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nullinux"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string1 = /\snullinux\.py/
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string2 = /\/nullinux\.git/
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string3 = /\/nullinux\.py/
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string4 = /\/nullinux_users\.txt/
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string5 = "/usr/local/bin/nullinux"
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string6 = /\]\sStarting\snullinux\ssetup\sscript/
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string7 = "e4df5a904c8eb505cb63d9905c398f632cf97ba193a6e25569d561d44f69e623"
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string8 = /enum_enumdomusers\(/
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string9 = "m8sec/nullinux"
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string10 = "nullinux -rid -range "
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string11 = "nullinux -shares -U "
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string12 = "nullinux -users "
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
