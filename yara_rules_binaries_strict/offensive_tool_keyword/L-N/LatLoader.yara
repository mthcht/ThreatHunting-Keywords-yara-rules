rule LatLoader
{
    meta:
        description = "Detection patterns for the tool 'LatLoader' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LatLoader"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string1 = /\sLatLoader\.py/ nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string2 = /\/LatLoader\.git/ nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string3 = /\/LatLoader\.py/ nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string4 = /\[\+\]\sLooking\sfor\sthe\sSSN\svia\sHalos\sGate/ nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string5 = /\\LatLoader\.py/ nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string6 = /\\LatLoader\-main/ nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string7 = "27f70a1d533f7a3b8703d89904ae4541d96c8c656661872a495f592f9ed80d9e" nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string8 = "45787955618ba3211b89021ddf23ecc5d2b55397a006190455c4070dad964572" nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string9 = /cmd\.exe\s\/c\sC\:\\\\Windows\\\\DiskSnapShot\.exe\s\&\&\secho\s\-\-path\sC\:\\\\Windows\\\\CCMCache\\\\cache/ nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string10 = "f0f8f8de178f91de8fe054b6450fa0d2291ad7693035f2c52df800e9168fb22d" nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string11 = "icyguider/LatLoader" nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string12 = "OPERATORCHANGEMEPLZZZ" nocase ascii wide
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
