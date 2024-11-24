rule BadPotato
{
    meta:
        description = "Detection patterns for the tool 'BadPotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BadPotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows Privilege Escalation Exploit BadPotato
        // Reference: https://github.com/BeichenDream/BadPotato
        $string1 = /\/BadPotato\.exe/ nocase ascii wide
        // Description: Windows Privilege Escalation Exploit BadPotato
        // Reference: https://github.com/BeichenDream/BadPotato
        $string2 = /\/BadPotato\.git/ nocase ascii wide
        // Description: Windows Privilege Escalation Exploit BadPotato
        // Reference: https://github.com/BeichenDream/BadPotato
        $string3 = /\\BadPotato\.csproj/ nocase ascii wide
        // Description: Windows Privilege Escalation Exploit BadPotato
        // Reference: https://github.com/BeichenDream/BadPotato
        $string4 = /\\BadPotato\.exe/ nocase ascii wide
        // Description: Windows Privilege Escalation Exploit BadPotato
        // Reference: https://github.com/BeichenDream/BadPotato
        $string5 = /\<BadPotato\.exe\>/ nocase ascii wide
        // Description: Windows Privilege Escalation Exploit BadPotato
        // Reference: https://github.com/BeichenDream/BadPotato
        $string6 = ">BadPotato<" nocase ascii wide
        // Description: Windows Privilege Escalation Exploit BadPotato
        // Reference: https://github.com/BeichenDream/BadPotato
        $string7 = "0527a14f-1591-4d94-943e-d6d784a50549" nocase ascii wide
        // Description: Windows Privilege Escalation Exploit BadPotato
        // Reference: https://github.com/BeichenDream/BadPotato
        $string8 = "063bc732edb5ca68d2122d0311ddb46dd38ff05074945566d1fa067c3579d767" nocase ascii wide
        // Description: Windows Privilege Escalation Exploit BadPotato
        // Reference: https://github.com/BeichenDream/BadPotato
        $string9 = /BadPotato\-master\.zip/ nocase ascii wide
        // Description: Windows Privilege Escalation Exploit BadPotato
        // Reference: https://github.com/BeichenDream/BadPotato
        $string10 = "BeichenDream/BadPotato" nocase ascii wide
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
