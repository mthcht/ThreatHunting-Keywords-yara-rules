rule Ikeext_Privesc
{
    meta:
        description = "Detection patterns for the tool 'Ikeext-Privesc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ikeext-Privesc"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string1 = /\/Ikeext\-Privesc\.git/ nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string2 = /\\Ikeext\-Privesc/ nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string3 = "57c1670e15a47e02637545cc4a3ad421000a98279df961fc6d454a5c0271421e" nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string4 = /DllInjection\.dll/ nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string5 = "IKEEXT DLL Hijacking" nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string6 = /Ikeext\-Privesc\.ps1/ nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string7 = "Invoke-IkeextCheck" nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string8 = "Invoke-IkeextExploit" nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string9 = "net stop IKEEXT" nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string10 = "securycore/Ikeext-Privesc" nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string11 = /The\sexploit\sis\sready\.\sA\sreboot\sis\snow\srequired\sto\strigger\sit/ nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string12 = /TVqQAAMAAAAEAAAA\/\/8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\+AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAADn8UE/ nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string13 = "W0lLRUVYVF0NCk1FRElBPXJhc3RhcGkNClBvcnQ9VlBOMi0wDQpEZXZpY2U9V2FuIE1pbmlwb3J0IChJS0V2MikNCkRFVklDRT12cG4NClBob25lTnVtYmVyPTEyNy4wLjAuMQ==" nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string14 = /wlbsctrl_payload\.bat/ nocase ascii wide
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
