rule BadWindowsService
{
    meta:
        description = "Detection patterns for the tool 'BadWindowsService' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BadWindowsService"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string1 = /\sBadWindowsService\.exe/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string2 = /\/BadWindowsService\.exe/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string3 = /\/BadWindowsService\.git/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string4 = /\\BadWindowsService\.cs/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string5 = /\\BadWindowsService\.exe/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string6 = /\\BadWindowsService\.sln/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string7 = /\\CurrentControlSet\\Services\\BadWindowsService/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string8 = /\\Program\sFiles\\Bad\sWindows\sService/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string9 = "1a88b6412bb1e6349948bc6abdc0eebb5df61cc8c0a7ec9709310a77dbc7bccb" nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string10 = "320ed251abc046f440dc0e76d00864d6cf5f65dee61988898d86c18e5513a8c9" nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string11 = "347e20ccd42d4346d9a1cb3255d77b493d3b1b52be12f72ccaa9085d6b5dd30f" nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string12 = "43A031B0-E040-4D5E-B477-02651F5E3D62" nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string13 = "4628fdac0a217dd268e3f962a7665348eb9cf64bda81313cbfb1617008a9dc2e" nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string14 = "6d820b495719031338017f6138fae3546f549e9e816274554f6c21a77149b778" nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string15 = "9a717740140d1848e3b2641af0a517cea689409951cb1262737b06ec398180e3" nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string16 = "acd65a0c933308d9a867fb3701e39787a386708fbaabd907d41b3decdb481ca2" nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string17 = "B474B962-A46B-4D35-86F3-E8BA120C88C0" nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string18 = /BadWindowsService_v1\.0\.7z/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string19 = /BadWindowsService_v1\.0\.zip/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string20 = "cc8bb64ef855405aeb66e480e8e7a2a65f61d495718fed2825083916cedd5e4c" nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string21 = "da8bf03ff487a649c28018f5e4d7bdac0e1ff1ed7ed67d6fa1b901c4dbc36a30" nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string22 = "eladshamir/BadWindowsService" nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string23 = /ServiceName.{0,100}BadWindowsService/ nocase ascii wide
        // Description: An insecurely implemented and installed Windows service for emulating elevation of privileges vulnerabilities
        // Reference: https://github.com/eladshamir/BadWindowsService
        $string24 = "ZeroPointSecurity/BadWindowsService" nocase ascii wide
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
