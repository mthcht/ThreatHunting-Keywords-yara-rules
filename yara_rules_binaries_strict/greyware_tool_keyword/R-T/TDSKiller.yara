rule TDSKiller
{
    meta:
        description = "Detection patterns for the tool 'TDSKiller' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TDSKiller"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: TDSKiller detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/kaspersky_tdsskiller.html
        $string1 = /\/TDSSKiller\.exe/ nocase ascii wide
        // Description: TDSKiller detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/kaspersky_tdsskiller.html
        $string2 = /\/tdsskiller\.zip/ nocase ascii wide
        // Description: TDSKiller detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/kaspersky_tdsskiller.html
        $string3 = /\\TDSSKiller\.exe/ nocase ascii wide
        // Description: TDSKiller detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/kaspersky_tdsskiller.html
        $string4 = /\\tdsskiller\.zip/ nocase ascii wide
        // Description: TDSKiller detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/kaspersky_tdsskiller.html
        $string5 = ">TDSS rootkit removing tool<" nocase ascii wide
        // Description: TDSKiller detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/kaspersky_tdsskiller.html
        $string6 = ">TDSSKiller<" nocase ascii wide
        // Description: TDSKiller detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/kaspersky_tdsskiller.html
        $string7 = "2d823c8b6076e932d696e8cb8a2c5c5df6d392526cba8e39b64c43635f683009" nocase ascii wide
        // Description: TDSKiller detect and remove malware - including rootkits but is also abused by attackers to disable antivirus
        // Reference: https://www.majorgeeks.com/files/details/kaspersky_tdsskiller.html
        $string8 = /http\:\/\/support\.kaspersky\.com\/viruses\/tdsskiller\.xmlt/ nocase ascii wide
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
