rule LostMyPassword
{
    meta:
        description = "Detection patterns for the tool 'LostMyPassword' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LostMyPassword"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string1 = /\\LostMyPassword\.cfg/ nocase ascii wide
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string2 = /\\LostMyPassword_lng\.ini/ nocase ascii wide
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string3 = /\\LostMyPassword32bit/ nocase ascii wide
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string4 = ">LostMyPassword<" nocase ascii wide
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string5 = "73882b9c273a72eb49fc2854de8b37ef3012115c0e62267acb8b955a681ec312" nocase ascii wide
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string6 = "745bdc69fd7d712f65419c126b3ab5524fb96a511a21fea2d2b261607b3b2c55" nocase ascii wide
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string7 = "7da421d00cd50570a79a82803c170d043fa3b2253ae2f0697e103072c34d39f1" nocase ascii wide
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string8 = /LostMyPassword\.exe/ nocase ascii wide
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string9 = /LostMyPassword\.zip/ nocase ascii wide
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string10 = /LostMyPasswordx64\.zip/ nocase ascii wide
        // Description: Nirsoft tool that allows you to recover a lost password if it's stored by a software installed on your system
        // Reference: https://www.nirsoft.net/alpha/lostmypassword-x64.zip
        $string11 = "Search your passwords as normal user" nocase ascii wide
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
