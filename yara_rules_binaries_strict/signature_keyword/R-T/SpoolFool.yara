rule SpoolFool
{
    meta:
        description = "Detection patterns for the tool 'SpoolFool' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpoolFool"
        rule_category = "signature_keyword"

    strings:
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string1 = "A Variant Of Win64/AddUser" nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string2 = "ATK/SpoolFool-A" nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string3 = /Exp\.CVE\-2022\-21999/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string4 = /Exploit\.CVE202222718\.MSIL/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string5 = /Generic\.Exploit\.CVE\-2022\-22718\.A\.2798221A/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string6 = /HEUR\:Exploit\.MSIL\.CVE\-2022\-22718\.gen/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string7 = /MSIL\/CVE_2022_22718\.A\!exploit/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string8 = /MSIL\/Exploit\.CVE\-2022\-22718\.A/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string9 = /Trojan\.AddUser/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string10 = /VirTool\:MSIL\/Spfolz\.A\!MTB/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string11 = /Win\.Exploit\.Exploitx\-9942911\-0/ nocase ascii wide
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
