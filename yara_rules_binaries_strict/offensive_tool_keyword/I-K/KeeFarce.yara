rule KeeFarce
{
    meta:
        description = "Detection patterns for the tool 'KeeFarce' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KeeFarce"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Extracts passwords from a KeePass 2.x database directly from memory
        // Reference: https://github.com/denandz/KeeFarce
        $string1 = /\/KeeFarce\.exe/ nocase ascii wide
        // Description: Extracts passwords from a KeePass 2.x database directly from memory
        // Reference: https://github.com/denandz/KeeFarce
        $string2 = /\/KeeFarce\.git/ nocase ascii wide
        // Description: Extracts passwords from a KeePass 2.x database directly from memory
        // Reference: https://github.com/denandz/KeeFarce
        $string3 = /\/KeeFarceDLL\.dll/ nocase ascii wide
        // Description: Extracts passwords from a KeePass 2.x database directly from memory
        // Reference: https://github.com/denandz/KeeFarce
        $string4 = /\[KeeFarceDLL\]/ nocase ascii wide
        // Description: Extracts passwords from a KeePass 2.x database directly from memory
        // Reference: https://github.com/denandz/KeeFarce
        $string5 = /\\KeeFarce\.exe/ nocase ascii wide
        // Description: Extracts passwords from a KeePass 2.x database directly from memory
        // Reference: https://github.com/denandz/KeeFarce
        $string6 = /\\KeeFarceDLL\.dll/ nocase ascii wide
        // Description: Extracts passwords from a KeePass 2.x database directly from memory
        // Reference: https://github.com/denandz/KeeFarce
        $string7 = /\\keepass_export\.csv/ nocase ascii wide
        // Description: Extracts passwords from a KeePass 2.x database directly from memory
        // Reference: https://github.com/denandz/KeeFarce
        $string8 = ">KeeFarceDLL<" nocase ascii wide
        // Description: Extracts passwords from a KeePass 2.x database directly from memory
        // Reference: https://github.com/denandz/KeeFarce
        $string9 = "0C3EB2F7-92BA-4895-99FC-7098A16FFE8C" nocase ascii wide
        // Description: Extracts passwords from a KeePass 2.x database directly from memory
        // Reference: https://github.com/denandz/KeeFarce
        $string10 = "17589EA6-FCC9-44BB-92AD-D5B3EEA6AF03" nocase ascii wide
        // Description: Extracts passwords from a KeePass 2.x database directly from memory
        // Reference: https://github.com/denandz/KeeFarce
        $string11 = "43d7e47e21d334bb7130c5709c16f02e2cf7e4a808382aed3c0ba12cc84b9ea9" nocase ascii wide
        // Description: Extracts passwords from a KeePass 2.x database directly from memory
        // Reference: https://github.com/denandz/KeeFarce
        $string12 = "51166803b9409224e3c4cdd77b61002707eed020e3d3e03ffa4b03dfabf1f7e4" nocase ascii wide
        // Description: Extracts passwords from a KeePass 2.x database directly from memory
        // Reference: https://github.com/denandz/KeeFarce
        $string13 = "5DE7F97C-B97B-489F-A1E4-9F9656317F94" nocase ascii wide
        // Description: Extracts passwords from a KeePass 2.x database directly from memory
        // Reference: https://github.com/denandz/KeeFarce
        $string14 = "5e87e7fe137ab8f51780b6646e74e942efa89a4ff95cb190dd0bf35a5dcf59e8" nocase ascii wide
        // Description: Extracts passwords from a KeePass 2.x database directly from memory
        // Reference: https://github.com/denandz/KeeFarce
        $string15 = "denandz/KeeFarce" nocase ascii wide
        // Description: Extracts passwords from a KeePass 2.x database directly from memory
        // Reference: https://github.com/denandz/KeeFarce
        $string16 = /HackTool\.MSIL\.KeeFarce/ nocase ascii wide
        // Description: Extracts passwords from a KeePass 2.x database directly from memory
        // Reference: https://github.com/denandz/KeeFarce
        $string17 = "HackTool:Win32/KeeFarce" nocase ascii wide
        // Description: Extracts passwords from a KeePass 2.x database directly from memory
        // Reference: https://github.com/denandz/KeeFarce
        $string18 = /Win\.Countermeasure\.KeeFarce/ nocase ascii wide
        // Description: Extracts passwords from a KeePass 2.x database directly from memory
        // Reference: https://github.com/denandz/KeeFarce
        $string19 = "Win32:KFarce-C" nocase ascii wide
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
