rule PySQLRecon
{
    meta:
        description = "Detection patterns for the tool 'PySQLRecon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PySQLRecon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Offensive MSSQL toolkit written in Python, based off SQLRecon
        // Reference: https://github.com/Tw1sm/PySQLRecon
        $string1 = /\/PySQLRecon\.git/ nocase ascii wide
        // Description: Offensive MSSQL toolkit written in Python, based off SQLRecon
        // Reference: https://github.com/Tw1sm/PySQLRecon
        $string2 = "/PySQLRecon/tarball" nocase ascii wide
        // Description: Offensive MSSQL toolkit written in Python, based off SQLRecon
        // Reference: https://github.com/Tw1sm/PySQLRecon
        $string3 = "/PySQLRecon/zipball" nocase ascii wide
        // Description: Offensive MSSQL toolkit written in Python, based off SQLRecon
        // Reference: https://github.com/Tw1sm/PySQLRecon
        $string4 = "2bcf6152e45cf60959f276a1e7482752895a5b17dc4d4a307a470c1a40284705" nocase ascii wide
        // Description: Offensive MSSQL toolkit written in Python, based off SQLRecon
        // Reference: https://github.com/Tw1sm/PySQLRecon
        $string5 = "55d72ecccc3e6bbf42653009b63e1c1e90b134714aca78dfd36ec35003bc3d76" nocase ascii wide
        // Description: Offensive MSSQL toolkit written in Python, based off SQLRecon
        // Reference: https://github.com/Tw1sm/PySQLRecon
        $string6 = "8213d434f255fbfba9d5432770a6b4ff85463271047384feba7176a301436634" nocase ascii wide
        // Description: Offensive MSSQL toolkit written in Python, based off SQLRecon
        // Reference: https://github.com/Tw1sm/PySQLRecon
        $string7 = "fde8744f64a41afea0aca93478a8e310a86dd3ac1e716bfdd6687e954ad2231e" nocase ascii wide
        // Description: Offensive MSSQL toolkit written in Python, based off SQLRecon
        // Reference: https://github.com/Tw1sm/PySQLRecon
        $string8 = "poetry run pysqlrecon" nocase ascii wide
        // Description: Offensive MSSQL toolkit written in Python, based off SQLRecon
        // Reference: https://github.com/Tw1sm/PySQLRecon
        $string9 = /pysqlrecon\.db/ nocase ascii wide
        // Description: Offensive MSSQL toolkit written in Python, based off SQLRecon
        // Reference: https://github.com/Tw1sm/PySQLRecon
        $string10 = /pysqlrecon\.lib/ nocase ascii wide
        // Description: Offensive MSSQL toolkit written in Python, based off SQLRecon
        // Reference: https://github.com/Tw1sm/PySQLRecon
        $string11 = /pysqlrecon\.logger/ nocase ascii wide
        // Description: Offensive MSSQL toolkit written in Python, based off SQLRecon
        // Reference: https://github.com/Tw1sm/PySQLRecon
        $string12 = "Tw1sm/PySQLRecon" nocase ascii wide
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
