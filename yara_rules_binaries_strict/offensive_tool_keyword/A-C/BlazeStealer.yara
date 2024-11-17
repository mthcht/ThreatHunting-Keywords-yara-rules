rule BlazeStealer
{
    meta:
        description = "Detection patterns for the tool 'BlazeStealer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BlazeStealer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string1 = /\/Pyobfadvance/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string2 = /\/Pyobfexecute/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string3 = /\/pyobfgood/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string4 = /\/Pyobflite/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string5 = /\/Pyobfpremium/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string6 = /\/Pyobftoexe/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string7 = /\/Pyobfuse/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string8 = /\/Pyobfusfile/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string9 = /\\Pyobfadvance/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string10 = /\\Pyobfexecute/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string11 = /\\pyobfgood/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string12 = /\\Pyobflite/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string13 = /\\Pyobfpremium/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string14 = /\\Pyobftoexe/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string15 = /\\Pyobfuse/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string16 = /\\Pyobfusfile/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string17 = /MTE2NTc2MDM5MjY5NDM1NDA2MA\.GRSNK7\.OHxJIpJoZxopWpF_S3zy5v2g7k2vyiufQ183Lo/ nocase ascii wide
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
