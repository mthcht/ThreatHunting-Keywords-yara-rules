rule pac2
{
    meta:
        description = "Detection patterns for the tool 'pac2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pac2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PAC2 is a framework that generates arbitrary flows and sends and executes them on the Power Automate Platform - using Power automate as a C2
        // Reference: https://github.com/NTT-Security-Japan/pac2
        $string1 = /\/c2_access\.log/
        // Description: PAC2 is a framework that generates arbitrary flows and sends and executes them on the Power Automate Platform - using Power automate as a C2
        // Reference: https://github.com/NTT-Security-Japan/pac2
        $string2 = /\/dummy\.pac2\.localhost/ nocase ascii wide
        // Description: PAC2 is a framework that generates arbitrary flows and sends and executes them on the Power Automate Platform - using Power automate as a C2
        // Reference: https://github.com/NTT-Security-Japan/pac2
        $string3 = "/mount/dropbox/Dropbox/pac2" nocase ascii wide
        // Description: PAC2 is a framework that generates arbitrary flows and sends and executes them on the Power Automate Platform - using Power automate as a C2
        // Reference: https://github.com/NTT-Security-Japan/pac2
        $string4 = "<h1>PowerAutomate C2 Portal" nocase ascii wide
        // Description: PAC2 is a framework that generates arbitrary flows and sends and executes them on the Power Automate Platform - using Power automate as a C2
        // Reference: https://github.com/NTT-Security-Japan/pac2
        $string5 = "77d2aa31773df8903d877f30db405b48896581f762b0d70e73e2c1014ea7b378" nocase ascii wide
        // Description: PAC2 is a framework that generates arbitrary flows and sends and executes them on the Power Automate Platform - using Power automate as a C2
        // Reference: https://github.com/NTT-Security-Japan/pac2
        $string6 = "a40ff8a806b8b2c385cd85e3c9627b09fca054a23fe7168aed459098266cab42" nocase ascii wide
        // Description: PAC2 is a framework that generates arbitrary flows and sends and executes them on the Power Automate Platform - using Power automate as a C2
        // Reference: https://github.com/NTT-Security-Japan/pac2
        $string7 = /from\s\.auth\simport\sPac2User/ nocase ascii wide
        // Description: PAC2 is a framework that generates arbitrary flows and sends and executes them on the Power Automate Platform - using Power automate as a C2
        // Reference: https://github.com/NTT-Security-Japan/pac2
        $string8 = /from\s\.dropbox\simport\sDropboxBeacon/ nocase ascii wide
        // Description: PAC2 is a framework that generates arbitrary flows and sends and executes them on the Power Automate Platform - using Power automate as a C2
        // Reference: https://github.com/NTT-Security-Japan/pac2
        $string9 = "hello_from_powerautomatec2" nocase ascii wide
        // Description: PAC2 is a framework that generates arbitrary flows and sends and executes them on the Power Automate Platform - using Power automate as a C2
        // Reference: https://github.com/NTT-Security-Japan/pac2
        $string10 = "http://localhost:9999/portal" nocase ascii wide
        // Description: PAC2 is a framework that generates arbitrary flows and sends and executes them on the Power Automate Platform - using Power automate as a C2
        // Reference: https://github.com/NTT-Security-Japan/pac2
        $string11 = "NTT-Security-Japan/pac2" nocase ascii wide
        // Description: PAC2 is a framework that generates arbitrary flows and sends and executes them on the Power Automate Platform - using Power automate as a C2
        // Reference: https://github.com/NTT-Security-Japan/pac2
        $string12 = /pac2\.localhost\:9999/ nocase ascii wide
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
