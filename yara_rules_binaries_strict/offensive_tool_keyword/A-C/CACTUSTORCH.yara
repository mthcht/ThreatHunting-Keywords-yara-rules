rule CACTUSTORCH
{
    meta:
        description = "Detection patterns for the tool 'CACTUSTORCH' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CACTUSTORCH"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1 = /\sCACTUSTORCH\.cna/ nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string2 = /\/CACTUSTORCH\.git/ nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string3 = "1cccdb0227ae73ae4c712460d12cf2fb9316568f2f8ceae6e6e3e101a8552942" nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string4 = "60c72ba7ed39768fd066dda3fdc75bcb5fae6efb3a0b222a3f455526dcf08c96" nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string5 = /CACTUSTORCH\.hta/ nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string6 = /CACTUSTORCH\.js/ nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string7 = /CACTUSTORCH\.vba/ nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string8 = /CACTUSTORCH\.vbe/ nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string9 = /CACTUSTORCH\.vbs/ nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string10 = "d9ce9dfbdd4f95ad01fc05855235d6894ef878d6d02706e6c91720ee8a4fb5bf" nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string11 = "mdsecactivebreach/CACTUSTORCH" nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string12 = "TM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAACf0hwW27NyRduzckXbs3JFZvzkRdqz" nocase ascii wide
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
