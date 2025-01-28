rule chaos
{
    meta:
        description = "Detection patterns for the tool 'chaos' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chaos"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string1 = /\schaos\.exe\s/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string2 = " SQLITE_DATABASE=chaos " nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string3 = " SQLITE_DATABASE=chaos" nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string4 = /\/CHAOS\.git/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string5 = /\/CHAOS\-5\.0\.1\.zip/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string6 = "/chaos-container:/database/" nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string7 = /\\chaos\.exe/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string8 = /\\CHAOS\-5\.0\.1\.zip/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string9 = /\\CHAOS\-master\.zip/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string10 = "3ec15909c169e37f1173d567cb4729f592002826ac0a0f5bf5e820af47195e78" nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string11 = "401ab31450e32d265a189983c56a0f7f947b15fe3559c08773275f6c1e6625ce" nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string12 = "48a61f194676d3b3f1aef3410eabda1ab57448f1966a91a2d1be5af02a2c77c8" nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string13 = "630cf7ac06f7286e926cfaf1b2ca5105a7caaee6627837da5f71d5b44302f992" nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string14 = "7c4650646cf661efd5ad7dc45f6237f6aa0cc28e81163ce1e3a7b86841cbd5f8" nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string15 = "7f994093b3133e5450cd89d4a9cc39cceca8bbcce8845665f86b4d7eb9998d61" nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string16 = "bfca678c800832025fe5e7c59bdf9bc3a2a62c77e7b689b943fee2821c2fec19" nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string17 = "c:/chaos-container:/database/" nocase ascii wide
        // Description: Chaos ransomware behavior
        // Reference: https://blog.qualys.com/vulnerabilities-threat-research/2022/01/17/the-chaos-ransomware-can-be-ravaging
        $string18 = /C\:\\Users\\.{0,100}\\AppData\\Roaming\\svchost\.exe/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string19 = /CHAOS\s\(Remote\sAdministration\sTool\)/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string20 = /chaos.{0,100}persistence_enable/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string21 = /docker.{0,100}\/chaos\-container\:\/temp\// nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string22 = "ec2a250f026c030d36c1f1d021816176a7a9a8f62f56673b418bca9154c5a3f1" nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string23 = /go\srun\scmd\/chaos\/main\.go/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string24 = /md\sc\:\\chaos\-container/ nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string25 = "tiagorlampert/CHAOS" nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string26 = "tiagorlampert/chaos:latest" nocase ascii wide
        // Description: CHAOS is a free and open-source Remote Administration Tool that allow generate binaries to control remote operating systems
        // Reference: https://github.com/tiagorlampert/CHAOS
        $string27 = /tiagorlampert\@gmail\.com/ nocase ascii wide
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
