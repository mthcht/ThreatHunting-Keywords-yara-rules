rule PS2EXE
{
    meta:
        description = "Detection patterns for the tool 'PS2EXE' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PS2EXE"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Convert Powershell scripts to EXEs
        // Reference: https://github.com/Leo4j/PS2EXE
        $string1 = /\sPS2EXE\.ps1/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string2 = /\/PS2EXE\.git/ nocase ascii wide
        // Description: Convert Powershell scripts to EXEs
        // Reference: https://github.com/Leo4j/PS2EXE
        $string3 = /\/PS2EXE\.ps1/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string4 = /\/PS2EXE\// nocase ascii wide
        // Description: Convert Powershell scripts to EXEs
        // Reference: https://github.com/Leo4j/PS2EXE
        $string5 = /\\PS2EXE\.ps1/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string6 = /\\Win\-PS2EXE/ nocase ascii wide
        // Description: Convert Powershell scripts to EXEs
        // Reference: https://github.com/Leo4j/PS2EXE
        $string7 = /760c4649c5acd734d931ee64ebfc62eb19fa5c45137f4712b84aba7a356cda91/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string8 = /Install\-Module\sps2exe/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string9 = /Invoke\-ps2exe/ nocase ascii wide
        // Description: Convert Powershell scripts to EXEs
        // Reference: https://github.com/Leo4j/PS2EXE
        $string10 = /Leo4j\/PS2EXE/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string11 = /MScholtes\/PS2EXE/ nocase ascii wide
        // Description: Convert Powershell scripts to EXEs
        // Reference: https://github.com/Leo4j/PS2EXE
        $string12 = /ps\.AddScript\(Encoding\.UTF8\.GetString\(Convert\.FromBase64String\(script\)/ nocase ascii wide
        // Description: Convert Powershell scripts to EXEs
        // Reference: https://github.com/Leo4j/PS2EXE
        $string13 = /PS1ToEXE.{0,100}PS2EXE\.ps1/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string14 = /ps2exe\s\-/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string15 = /ps2exe\s.{0,100}\.ps1.{0,100}\.exe/ nocase ascii wide
        // Description: Convert Powershell scripts to EXEs
        // Reference: https://github.com/Leo4j/PS2EXE
        $string16 = /PS2EXE\s\-content\s\$.{0,100}\s\-outputFile\s/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string17 = /ps2exe\.ps1/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string18 = /ps2exe\.psd1/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string19 = /ps2exe\.psm1/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string20 = /PS2EXE\-master/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string21 = /Win\-PS2EXE\.exe/ nocase ascii wide
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
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
