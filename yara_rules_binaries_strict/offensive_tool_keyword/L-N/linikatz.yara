rule linikatz
{
    meta:
        description = "Detection patterns for the tool 'linikatz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "linikatz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string1 = /\/linikatz\.git/
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string2 = "/vas/fuzzers/fuzz/"
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string3 = "12e9256bbb969343cc20fa9e259c0af1bf12d6c7bd0263bd7b2a60575b73cf62"
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string4 = "4681186a8bcaff98f0d2513d30add67345491b95f7f743883e6ca2506ba7aaaf"
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string5 = "612789c90ec1040d821a985265ea3b2f57e2c8df90b3880752dcb869e45256bc"
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string6 = "66c368f799227a9b571f841057e2d5f12c862360d5f7f564da9936acd67c66a0"
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string7 = "691f577714a4ae22bc22ec49edec5a15bf546a9827e8e1cf4e9e688b2ba9f72e"
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string8 = "8672d46e879f704b4b41a401c1a0aae5e6365f18a798a1fbaa4b1a8e711db34b"
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string9 = "9a3a44c544cd596ebf94583614035575e746f57315e20ec56a819c7152ba3fe9"
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string10 = "a0101bdeeb3f99c0640c203716381ef9f6bad8e89973eaa608c801ed3f6ccace"
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string11 = "a1b3d36a9cc4bc118c646ae5430a6e0fc811f2ec3614a3de9682b5c07eaade2d"
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string12 = "adf6d464ce449914110607706da329993186f52f99074af1b7b1734a46dd4fcf"
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string13 = "b2363d2b238f9336bb270fe96db258243668a916d7ddf94bf3a3126ed7cae508"
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string14 = "b8ad30b89d6cabe30501ed963b21dcaec70b3283608682678629feae2c1b2235"
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string15 = "C34208EA-8C33-473D-A9B4-53FB40347EA0"
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string16 = "cbeecb2981c75b8f066b1f04f19f2095bdcf22f19d0d3f1099b83963547c00cb"
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string17 = "CiscoCXSecurity/linikatz"
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string18 = /config_steal\s\/etc\/krb5\.conf\s\/etc\/krb5\.keytab/
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string19 = "e69a6f8e45f8dd8ee977b6aed73cac25537c39f6fb74cf9cc225f2af1d9e4cd7"
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string20 = /ERPScan\-tockenchpoken\.zip/
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string21 = "f1696fdc28bdb9e757a14b2ba9e698af8f70bb928d3c9e9fb524249f20231d08"
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string22 = "f3aacbbaacceb0bdcac49d9b5e1da52d6883b7d736ca68f0a98f5a1d4838b995"
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string23 = /fuzzers\/rippackets\.pl/
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string24 = /linikatz\.sh/
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string25 = /linikatz\.zip/
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string26 = "P0rtcu11i5!"
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string27 = /unix_cached_ad_hashes\.rb/
        // Description: linikatz is a tool to attack AD on UNIX
        // Reference: https://github.com/CiscoCXSecurity/linikatz
        $string28 = /unix_kerberos_tickets\.rb/
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
