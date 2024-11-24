rule Venom
{
    meta:
        description = "Detection patterns for the tool 'Venom' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Venom"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string1 = /\sport_reuse\.py/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string2 = " --string 'venomcoming' " nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string3 = " --string 'venomleaving' " nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string4 = /\/port_reuse\.py/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string5 = /\/Venom\.git/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string6 = /\/Venom\.v1\.0\.1\.7z/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string7 = /\/Venom\.v1\.0\.2\.7z/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string8 = /\/Venom\.v1\.0\.7z/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string9 = /\/Venom\.v1\.1\.0\.7z/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string10 = "/Venom/tarball/v" nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string11 = "/Venom/zipball/v" nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string12 = /\\port_reuse\.py/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string13 = /\\Venom\.v1\.0\.1\.7z/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string14 = /\\Venom\.v1\.0\.2\.7z/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string15 = /\\Venom\.v1\.0\.7z/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string16 = /\\Venom\.v1\.1\.0\.7z/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string17 = "37da8267b295caeca8fadb13206ba1c498a7012673430c5d856fe93862446a28" nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string18 = "52907aebc7d2c6534099d149e61bf294b0ddf7d4e814a72b3621e3a829f83c97" nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string19 = /admin_macos_x64\s\-rhost\s.{0,100}\s\-rport\s/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string20 = /agent\.exe\s\-lhost\s.{0,100}\s\-reuse\-port\s/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string21 = "agent_linux_x64 -lport " nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string22 = /agent_linux_x64\s\-rhost\s.{0,100}\s\-rport\s/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string23 = "Venom Admin Node Start" nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string24 = /Venom\\agent\\agent\.go/ nocase ascii wide
        // Description: Venom - A Multi-hop Proxy for Penetration Testers
        // Reference: https://github.com/Dliv3/Venom
        $string25 = "You can execute commands in this shell :D" nocase ascii wide
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
