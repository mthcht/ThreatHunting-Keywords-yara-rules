rule winexe
{
    meta:
        description = "Detection patterns for the tool 'winexe' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "winexe"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Winexe remotely executes commands on Windows systems from GNU/Linux
        // Reference: https://www.kali.org/tools/winexe/
        $string1 = "/kalilinux/packages/winexe" nocase ascii wide
        // Description: Winexe remotely executes commands on Windows systems from GNU/Linux
        // Reference: https://www.kali.org/tools/winexe/
        $string2 = /\/winexe\s.{0,100}\-\-runas/ nocase ascii wide
        // Description: Winexe remotely executes commands on Windows systems from GNU/Linux
        // Reference: https://www.kali.org/tools/winexe/
        $string3 = "/winexe -U " nocase ascii wide
        // Description: Winexe remotely executes commands on Windows systems from GNU/Linux
        // Reference: https://www.kali.org/tools/winexe/
        $string4 = /\/winexe\.git/ nocase ascii wide
        // Description: Winexe remotely executes commands on Windows systems from GNU/Linux
        // Reference: https://www.kali.org/tools/winexe/
        $string5 = /\/winexe\-0\.91\.tar\.gz/ nocase ascii wide
        // Description: Winexe remotely executes commands on Windows systems from GNU/Linux
        // Reference: https://www.kali.org/tools/winexe/
        $string6 = /\/winexe\-1\.00\.tar\.gz/ nocase ascii wide
        // Description: Winexe remotely executes commands on Windows systems from GNU/Linux
        // Reference: https://www.kali.org/tools/winexe/
        $string7 = /\\winexesvc\.exe/ nocase ascii wide
        // Description: Winexe remotely executes commands on Windows systems from GNU/Linux
        // Reference: https://www.kali.org/tools/winexe/
        $string8 = ">winexesvc<" nocase ascii wide
        // Description: Winexe remotely executes commands on Windows systems from GNU/Linux
        // Reference: https://www.kali.org/tools/winexe/
        $string9 = "2077c0c96383793ffa5b0843740f9b095688df5f5accd1a74c65f634bbc42358" nocase ascii wide
        // Description: Winexe remotely executes commands on Windows systems from GNU/Linux
        // Reference: https://www.kali.org/tools/winexe/
        $string10 = "60f25c8a290ba6185b07da48663cfc4662e2853e324bef2a272aede4c15260d2" nocase ascii wide
        // Description: Winexe remotely executes commands on Windows systems from GNU/Linux
        // Reference: https://www.kali.org/tools/winexe/
        $string11 = "99238bd3e1c0637041c737c86a05bd73a9375abc9794dca71d2765e22d87537e" nocase ascii wide
        // Description: Winexe remotely executes commands on Windows systems from GNU/Linux
        // Reference: https://www.kali.org/tools/winexe/
        $string12 = "apt install winexe" nocase ascii wide
        // Description: Winexe remotely executes commands on Windows systems from GNU/Linux
        // Reference: https://www.kali.org/tools/winexe/
        $string13 = /https\:\/\/sourceforge\.net\/projects\/winexe/ nocase ascii wide
        // Description: Winexe remotely executes commands on Windows systems from GNU/Linux
        // Reference: https://www.kali.org/tools/winexe/
        $string14 = "skalkoto/winexe" nocase ascii wide
        // Description: Winexe remotely executes commands on Windows systems from GNU/Linux
        // Reference: https://www.kali.org/tools/winexe/
        $string15 = /winexesvc32\.exe/ nocase ascii wide
        // Description: Winexe remotely executes commands on Windows systems from GNU/Linux
        // Reference: https://www.kali.org/tools/winexe/
        $string16 = /winexesvc64\.exe/ nocase ascii wide
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
