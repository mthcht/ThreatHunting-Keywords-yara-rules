rule SharpBruteForceSSH
{
    meta:
        description = "Detection patterns for the tool 'SharpBruteForceSSH' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpBruteForceSSH"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: simple SSH brute force tool 
        // Reference: https://github.com/HernanRodriguez1/SharpBruteForceSSH
        $string1 = /\/SharpBruteForceSSH\.git/ nocase ascii wide
        // Description: simple SSH brute force tool 
        // Reference: https://github.com/HernanRodriguez1/SharpBruteForceSSH
        $string2 = /\\SharpBruteForceSSH\-main/ nocase ascii wide
        // Description: simple SSH brute force tool 
        // Reference: https://github.com/HernanRodriguez1/SharpBruteForceSSH
        $string3 = "2f3c1b3378d19418aa4c99685f3ab9d6730c132a920946b64c0e4edc9efd5ed6" nocase ascii wide
        // Description: simple SSH brute force tool 
        // Reference: https://github.com/HernanRodriguez1/SharpBruteForceSSH
        $string4 = "4775208998622726a1b1a5f156e6e88b2ba4e568416795c19358d7380c35b0b8" nocase ascii wide
        // Description: simple SSH brute force tool 
        // Reference: https://github.com/HernanRodriguez1/SharpBruteForceSSH
        $string5 = "9ec223a7538868ec25a3823217038beedef36d8dd1f8e388c056bf79fd864b93" nocase ascii wide
        // Description: simple SSH brute force tool 
        // Reference: https://github.com/HernanRodriguez1/SharpBruteForceSSH
        $string6 = "Brute forcing passwords for " nocase ascii wide
        // Description: simple SSH brute force tool 
        // Reference: https://github.com/HernanRodriguez1/SharpBruteForceSSH
        $string7 = "Dictionary brute force attack on SSH services" nocase ascii wide
        // Description: simple SSH brute force tool 
        // Reference: https://github.com/HernanRodriguez1/SharpBruteForceSSH
        $string8 = "f0b1a06aa6d5ea27814565755c6bfe2520dd71c4df02768fe7d621c3c3d0db75" nocase ascii wide
        // Description: simple SSH brute force tool 
        // Reference: https://github.com/HernanRodriguez1/SharpBruteForceSSH
        $string9 = "HernanRodriguez1/SharpBruteForceSSH" nocase ascii wide
        // Description: simple SSH brute force tool 
        // Reference: https://github.com/HernanRodriguez1/SharpBruteForceSSH
        $string10 = /SharpBruteForceSSH\.cs/ nocase ascii wide
        // Description: simple SSH brute force tool 
        // Reference: https://github.com/HernanRodriguez1/SharpBruteForceSSH
        $string11 = /SharpBruteForceSSH\.exe/ nocase ascii wide
        // Description: simple SSH brute force tool 
        // Reference: https://github.com/HernanRodriguez1/SharpBruteForceSSH
        $string12 = /sshBruteForce\.exe/ nocase ascii wide
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
