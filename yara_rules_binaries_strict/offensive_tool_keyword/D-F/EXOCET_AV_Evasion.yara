rule EXOCET_AV_Evasion
{
    meta:
        description = "Detection patterns for the tool 'EXOCET-AV-Evasion' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EXOCET-AV-Evasion"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string1 = /\sexocet\.go\s.{0,100}\.exe/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string2 = /\/exocet\.elf/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string3 = /\/exocet\.exe/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string4 = /\/EXOCET\-AV\-Evasion\.git/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string5 = /\\beacon\-in\-go\.exe/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string6 = /\\exocet\.elf/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string7 = /\\exocet\.exe/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string8 = /\\inline\-shellcode\-test\.c/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string9 = /EXOCET\-AV\-Evasion\-master/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string10 = /exocet\-shellcode\-exec\-redo\.go/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string11 = /func\sdecryptMalware\(/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string12 = /meterpreter\-in\-go\.exe/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string13 = /Output\smalware\ssample\sselected\:\s/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string14 = /tanc7\/EXOCET\-AV\-Evasion/ nocase ascii wide
        // Description: EXOCET - AV-evading undetectable payload delivery tool
        // Reference: https://github.com/tanc7/EXOCET-AV-Evasion
        $string15 = /The\smalware\sGo\sfile\shas\sbeen\scompleted\./ nocase ascii wide
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
