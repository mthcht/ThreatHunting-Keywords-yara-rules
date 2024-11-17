rule sharphound
{
    meta:
        description = "Detection patterns for the tool 'sharphound' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sharphound"
        rule_category = "signature_keyword"

    strings:
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string1 = /3f31295f3435ec6223bbd70a6c0d4620a344e2232c7255dd8fa84ed48aa7a59a/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string2 = /ATK\/BloodH\-B/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string3 = /HackTool\.MSIL\.SharpHound/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string4 = /Hacktool\.SharpHound/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string5 = /HackTool\:W32\/SharpHound/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string6 = /Trojan\:Win32\/Sabsik\.TE\.B\!ml/ nocase ascii wide
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
