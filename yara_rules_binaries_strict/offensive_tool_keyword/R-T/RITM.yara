rule RITM
{
    meta:
        description = "Detection patterns for the tool 'RITM' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RITM"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string1 = " import Spoofer, Sniffer, Roaster" nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string2 = /\sroaster\.py/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string3 = /\ssniffer\.py/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string4 = /\sspoofer\.py/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string5 = /\/RITM\.git/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string6 = /\/roaster\.py/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string7 = /\/sniffer\.py/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string8 = /\/spoofer\.py/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string9 = /\\roaster\.py/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string10 = /\\sniffer\.py/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string11 = /\\spoofer\.py/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string12 = "387e21adbabeddf80db5d2868f93d6bdba8443dc26fdb964ec6e279f3d02310c" nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string13 = "ad393f135cc101f7897812ad3183775a89853e89cab5f31ae89eef3240ca9c4f" nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string14 = "f1525ffa97500a9aa64138541d1e91f403e494d8a6eef7bcb1f1de7e8261755e" nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string15 = /from\sritm\.lib\simport\s/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string16 = /from\sritm\.logger\simport\s/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string17 = /I\sneed\sroooot\.\sUnable\sto\sopen\s/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string18 = /impacket\.krb5\./ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string19 = "poetry run ritm " nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string20 = "'Roasted SPN " nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string21 = "Sniffed AS-REQ from " nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string22 = "Sniffer waiting for AS-REQ" nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string23 = "The AS-REQ is valid! Attempting to roast " nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string24 = "Tw1sm/RITM" nocase ascii wide
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
