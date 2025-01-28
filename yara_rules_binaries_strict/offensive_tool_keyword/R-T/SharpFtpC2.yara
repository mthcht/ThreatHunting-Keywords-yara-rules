rule SharpFtpC2
{
    meta:
        description = "Detection patterns for the tool 'SharpFtpC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpFtpC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems.
        // Reference: https://github.com/DarkCoderSc/SharpFtpC2
        $string1 = "/FtpC2/" nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // Reference: https://github.com/PhrozenIO/SharpFtpC2
        $string2 = /\/SharpFtpC2\.git/ nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // Reference: https://github.com/PhrozenIO/SharpFtpC2
        $string3 = "/SharpFtpC2/tarball/" nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // Reference: https://github.com/PhrozenIO/SharpFtpC2
        $string4 = "/SharpFtpC2/zipball/" nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // Reference: https://github.com/PhrozenIO/SharpFtpC2
        $string5 = /\\FtpC2\.sln/ nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems.
        // Reference: https://github.com/DarkCoderSc/SharpFtpC2
        $string6 = /\\FtpC2\\/ nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // Reference: https://github.com/PhrozenIO/SharpFtpC2
        $string7 = /\\FtpC2\\FtpC2\\/ nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems.
        // Reference: https://github.com/DarkCoderSc/SharpFtpC2
        $string8 = /\\net.{0,100}\\ftpagent\.exe/ nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // Reference: https://github.com/PhrozenIO/SharpFtpC2
        $string9 = /\\SharpFtpC2/ nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // Reference: https://github.com/PhrozenIO/SharpFtpC2
        $string10 = "17ff8cdd3a77ef0f0106b2b0d8e639f3424ec597c4853a53ebe25433b679707c" nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // Reference: https://github.com/PhrozenIO/SharpFtpC2
        $string11 = "1E474090-96A7-433C-BFE6-0F8B45DECC42" nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // Reference: https://github.com/PhrozenIO/SharpFtpC2
        $string12 = "2704649168fdd21796f1a46221a6e133105230e88070863976733d386a6ab204" nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // Reference: https://github.com/PhrozenIO/SharpFtpC2
        $string13 = "3b7eb2083f99deb0f6d2d64030f6ca6ec26e643226d981f7294b0c5340eaa733" nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // Reference: https://github.com/PhrozenIO/SharpFtpC2
        $string14 = "44D0366D-742F-4E0B-A67D-3B1044A66EA7" nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // Reference: https://github.com/PhrozenIO/SharpFtpC2
        $string15 = "6376A5B0-1BA8-4854-B81E-F5DC072C0FEE" nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // Reference: https://github.com/PhrozenIO/SharpFtpC2
        $string16 = "6c0aaa05f8c75791a7bd4e950183d25276d70476a4ba243801dd47e5329a185d" nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // Reference: https://github.com/PhrozenIO/SharpFtpC2
        $string17 = "8839f297dba4758e6c37d5b13f6fb47e19338798a2e4e61cef77d2423fcf7eef" nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // Reference: https://github.com/PhrozenIO/SharpFtpC2
        $string18 = "89fb18f0ffce36584def6266ae92f8b5273f2d89de96772625845f77c64ef0dc" nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // Reference: https://github.com/PhrozenIO/SharpFtpC2
        $string19 = "8b88db25c32e31d7b139b916e2df8aa3662b93a072077c26f3319a0978cb05e4" nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // Reference: https://github.com/PhrozenIO/SharpFtpC2
        $string20 = "8c81afc8fcbd100d5793d4c31399e10132f74c77212655c73799ebea7fe95dc3" nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // Reference: https://github.com/PhrozenIO/SharpFtpC2
        $string21 = "9bb557700cb82541b43da98c6d4eac110289b54736350ba7d4467ca783f950a7" nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // Reference: https://github.com/PhrozenIO/SharpFtpC2
        $string22 = "d0b6d53a899a02e580e7040a2c442ec872d3edc1c6d8eb4e82b95b0bf2e70943" nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems.
        // Reference: https://github.com/DarkCoderSc/SharpFtpC2
        $string23 = /FtpC2\.exe/ nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems.
        // Reference: https://github.com/DarkCoderSc/SharpFtpC2
        $string24 = /FtpC2\.Tasks/ nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // Reference: https://github.com/PhrozenIO/SharpFtpC2
        $string25 = /jplesueur\@phrozen\.io/ nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems
        // Reference: https://github.com/PhrozenIO/SharpFtpC2
        $string26 = "PhrozenIO/SharpFtpC2" nocase ascii wide
        // Description: A Streamlined FTP-Driven Command and Control Conduit for Interconnecting Remote Systems.
        // Reference: https://github.com/DarkCoderSc/SharpFtpC2
        $string27 = "SharpFtpC2" nocase ascii wide
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
