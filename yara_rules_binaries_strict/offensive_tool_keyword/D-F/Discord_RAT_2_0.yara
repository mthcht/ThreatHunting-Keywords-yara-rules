rule Discord_RAT_2_0
{
    meta:
        description = "Detection patterns for the tool 'Discord-RAT-2.0' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Discord-RAT-2.0"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string1 = /\/Discord\srat\.exe/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string2 = /\/Discord\-RAT\-2\.0/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string3 = /\/Discord\-RAT\-2\.0\.git/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string4 = /\/InstallStager\.exe/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string5 = /\/PasswordStealer\.dll/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string6 = /\/Resources\/Webcam\.dll/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string7 = /\/rootkit\.dll/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string8 = /\/run\s\/tn\s\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup\s\/I/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string9 = /\/Token\%20grabber\.dll/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string10 = /\/unrootkit\.dll/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string11 = /\\Discord\srat\.exe/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string12 = /\\Discord\-RAT\-2\.0/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string13 = /\\Discord\-RAT\-2\.0\-main/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string14 = /\\InstallStager\.exe/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string15 = /\\InstallStager\.pdb/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string16 = /\\PasswordStealer\.dll/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string17 = /\\rootkit\.dll/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string18 = /\\Token\sgrabber\.dll/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string19 = /\\unrootkit\.dll/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string20 = "10804539a495e0fcc79a6c2ab03e34d4b5c2bce1e134060839ff9b58dcfc1cf7" nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string21 = "121e18a8ad050f1a9510c6c32c0f4bb9adac3436170e2d1966788da4dc14c751" nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string22 = "4350a69f2630214a7b079e41e3ac2d7c5759a622a0cd1227ba12eee06d758d9a" nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string23 = "8fdae5b4490183c9057a684f0ac2f82dd5c8911cb2f43a54ff47a9ad6e93952a" nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string24 = "a3ca8d72edaf4ffb84a38e88a31f9e537d7d7b76f7cc7966583c7b4b4a811c74" nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string25 = "Advfirewall set allprofiles state off" nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string26 = "ae8abf10e555cee9769abea0e2d3379b11bc6a817f75a0b6038d294fa3d6a136" nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string27 = "c13a0cd7c2c2fd577703bff026b72ed81b51266afa047328c8ff1c4a4d965c97" nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string28 = "CC12258F-AF24-4773-A8E3-45D365BCBDE9" nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string29 = "cd075baa8305d9767316d5a2cc0ee60daf1f194a3c4b0d3386d1f8bd80f44907" nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string30 = "DBAE6A6E-AE23-4DE9-9AB2-6A8D2CD59DEF" nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string31 = "de314bd66c919dbd7b5e6614583f44a6461a1663f880873bc6746eed3a149457" nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string32 = "df78d4f9127039231844797c38428df24a80bd49eb11a5ee9a4dcf43f31573a9" nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string33 = /Discord\-RAT\-2\.0\-discordrat\.zip/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string34 = /Discord\-RAT\-2\.0\-master\.zip/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string35 = "Discord-RAT-by-Biscuit-main" nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string36 = "E776B801-614D-4E3C-A446-5A35B0CF3D08" nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string37 = "FAA8C7E2-4409-44F5-B2CA-EBBA4D4F41F0" nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string38 = /httpClient\.PostAsync\(\\"https\:\/\/file\.io\// nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string39 = /moom825\/Discord\-RAT\-2\.0/ nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string40 = "namespace Discord_rat" nocase ascii wide
        // Description: Discord Remote Administration Tool fully written in c#, stub size of ~75kb with over 40 post exploitations modules
        // Reference: https://github.com/moom825/Discord-RAT-2.0
        $string41 = /SOFTWARE\\\$77config\\/ nocase ascii wide
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
