rule VeamHax
{
    meta:
        description = "Detection patterns for the tool 'VeamHax' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VeamHax"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Exploit for CVE-2023-27532 against Veeam Backup & Replication (Plaintext credential leaking tool)
        // Reference: https://github.com/sfewer-r7/CVE-2023-27532
        $string1 = /\s\-\-sql\s\\"EXEC\smaster\.\.xp_cmdshell/ nocase ascii wide
        // Description: Exploit for CVE-2023-27532 against Veeam Backup & Replication (Plaintext credential leaking tool)
        // Reference: https://github.com/sfewer-r7/CVE-2023-27532
        $string2 = " --sql \"EXEC sp_configure 'xp_cmdshell'" nocase ascii wide
        // Description: Exploit for CVE-2023-27532 against Veeam Backup & Replication (Plaintext credential leaking tool)
        // Reference: https://github.com/sfewer-r7/CVE-2023-27532
        $string3 = " --sql \"EXEC sp_configure 'xp_cmdshell', '1'" nocase ascii wide
        // Description: Exploit for CVE-2023-27532 against Veeam Backup & Replication (Plaintext credential leaking tool)
        // Reference: https://github.com/sfewer-r7/CVE-2023-27532
        $string4 = /\sVeeamHax\.exe/ nocase ascii wide
        // Description: Exploit for CVE-2023-27532 against Veeam Backup & Replication (Plaintext credential leaking tool)
        // Reference: https://github.com/sfewer-r7/CVE-2023-27532
        $string5 = /\/VeeamHax\.exe/ nocase ascii wide
        // Description: Exploit for CVE-2023-27532 against Veeam Backup & Replication (Plaintext credential leaking tool)
        // Reference: https://github.com/sfewer-r7/CVE-2023-27532
        $string6 = /\\VeeamHax\.exe/ nocase ascii wide
        // Description: Exploit for CVE-2023-27532 against Veeam Backup & Replication (Plaintext credential leaking tool)
        // Reference: https://github.com/sfewer-r7/CVE-2023-27532
        $string7 = /\\VeeamHax\.pdb/ nocase ascii wide
        // Description: Exploit for CVE-2023-27532 against Veeam Backup & Replication (Plaintext credential leaking tool)
        // Reference: https://github.com/sfewer-r7/CVE-2023-27532
        $string8 = /\\VeeamHax\.sln/ nocase ascii wide
        // Description: Exploit for CVE-2023-27532 against Veeam Backup & Replication (Plaintext credential leaking tool)
        // Reference: https://github.com/sfewer-r7/CVE-2023-27532
        $string9 = "2ffb7bfe8f888c083361a65e7a8a349ba1f6b16971522011f545029fb20b3fd1" nocase ascii wide
        // Description: Exploit for CVE-2023-27532 against Veeam Backup & Replication (Plaintext credential leaking tool)
        // Reference: https://github.com/sfewer-r7/CVE-2023-27532
        $string10 = "59c2e7b63bbfe6dbabdd384973817bc26433c9c90ce755a9f7ec2627a949f65b" nocase ascii wide
        // Description: Exploit for CVE-2023-27532 against Veeam Backup & Replication (Plaintext credential leaking tool)
        // Reference: https://github.com/sfewer-r7/CVE-2023-27532
        $string11 = "67a426a646b50409aaaf70383a7f6b4b10981034623b4089a32fabb839997656" nocase ascii wide
        // Description: Exploit for CVE-2023-27532 against Veeam Backup & Replication (Plaintext credential leaking tool)
        // Reference: https://github.com/sfewer-r7/CVE-2023-27532
        $string12 = "A96C7C34-5791-43CF-9F8B-8EF5B3FB6EBA" nocase ascii wide
        // Description: Exploit for CVE-2023-27532 against Veeam Backup & Replication (Plaintext credential leaking tool)
        // Reference: https://github.com/sfewer-r7/CVE-2023-27532
        $string13 = "aaa6041912a6ba3cf167ecdb90a434a62feaf08639c59705847706b9f492015d" nocase ascii wide
        // Description: Exploit for CVE-2023-27532 against Veeam Backup & Replication (Plaintext credential leaking tool)
        // Reference: https://github.com/sfewer-r7/CVE-2023-27532
        $string14 = "f6888c1406e2b3549c9bc11929595170d3a74b0d4968f603cc33f9a896a53a95" nocase ascii wide
        // Description: Exploit for CVE-2023-27532 against Veeam Backup & Replication (Plaintext credential leaking tool)
        // Reference: https://github.com/sfewer-r7/CVE-2023-27532
        $string15 = "sfewer-r7/CVE-2023-27532" nocase ascii wide
        // Description: Exploit for CVE-2023-27532 against Veeam Backup & Replication (Plaintext credential leaking tool)
        // Reference: https://github.com/sfewer-r7/CVE-2023-27532
        $string16 = /VeeamHax_TemporaryKey\.pfx/ nocase ascii wide
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
