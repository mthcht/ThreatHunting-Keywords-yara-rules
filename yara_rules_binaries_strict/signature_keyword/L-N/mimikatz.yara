rule mimikatz
{
    meta:
        description = "Detection patterns for the tool 'mimikatz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mimikatz"
        rule_category = "signature_keyword"

    strings:
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string1 = /Gen\:Variant\.Mimikatz/ nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string2 = /HackTool\.Mimikatz/ nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string3 = "HackTool/Mimikatz" nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string4 = "HackTool:Win32/Mimilove" nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string5 = /HEUR\:Trojan\-PSW\.Win64\.Mimilove/ nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string6 = "HKTL_MIMIKATZ" nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string7 = /Mimikatz\.Spyware\.Stealer\.DDS/ nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string8 = /Trojan\/Win\.Mimikatz/ nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string9 = /Trojan\-PSW\.Win64\.Mimilove/ nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string10 = /Win32\.Mimikatz/ nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string11 = /Win32\/Riskware\.Mimikatz/ nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string12 = /Win64\.Mimikatz/ nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string13 = "Win64/Riskware Mimikatz" nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string14 = /Win64\/Riskware\.Mimikatz/ nocase ascii wide
        // Description: Mimikatz AV signatures
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string15 = /Win64\/Riskware\.Mimikatz/ nocase ascii wide
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
