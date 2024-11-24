rule POSTDump
{
    meta:
        description = "Detection patterns for the tool 'POSTDump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "POSTDump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string1 = /\sPostDump\.exe/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string2 = /\.exe\s\-\-signature\s\-\-driver/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string3 = /\/PostDump\.exe/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string4 = /\/PostDump\.exe/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string5 = /\/PostDump\.exe/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string6 = /\/POSTDump\.git/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string7 = /\/POSTDump\.git/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string8 = /\/POSTDump\.sln/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string9 = /\\lsass\.dmp/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string10 = /\\POSTDump\.csproj/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string11 = /\\PostDump\.exe/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string12 = /\\PostDump\.exe/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string13 = /\\PostDump\.exe/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string14 = /\\POSTDump\.sln/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string15 = /\\POSTDump\.sln/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string16 = /\\POSTDump\\POSTDump\\/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string17 = /\\POSTMiniDump\\/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string18 = /\\POSTMiniDump\\/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string19 = /ASR_bypass_to_dump_LSASS\./ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string20 = /ASR_bypass_to_dump_LSASS\.cs/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string21 = /copy\s.{0,100}PROCEXP\.sys.{0,100}C\:\\Windows\\System32\\WindowsPowershell\\/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string22 = /Done\!\sCheck\sfor\sexisting\slsass\.dmp\sfile\sinto\scurrent\sfolder/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string23 = "E54195F0-060C-4B24-98F2-AD9FB5351045" nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string24 = "E54195F0-060C-4B24-98F2-AD9FB5351045" nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string25 = "E54195F0-060C-4B24-98F2-AD9FB5351045" nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string26 = "Invoke-PostDump" nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string27 = "namespace POSTDump" nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string28 = "namespace POSTMiniDump" nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string29 = /POSTDump.{0,100}PROCEXP\.sys/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string30 = /POSTDump\.csproj/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string31 = /POSTDump\.csproj/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string32 = /PostDump\.exe\s/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string33 = /PostDump\.exe\s/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string34 = /PostDump\.exe\s/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string35 = /POSTDump\.git/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string36 = /PostDump\.ps1/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string37 = /POSTDump\\Postdump\.cs/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string38 = /POSTDump\\PROCEXP\.sys/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string39 = "POSTDump-main" nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string40 = "POSTDump-main" nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string41 = "POSTDump-main" nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string42 = /POSTMiniDump\.Data/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string43 = /POSTMiniDump\.Data/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string44 = /POSTMiniDump\.MiniDump/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string45 = /POSTMiniDump\.MiniDump/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string46 = /POSTMiniDump\.Utils/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string47 = /python3\sdump\-restore\.py\s.{0,100}\.dmp\s\-\-type\srestore/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string48 = /python3\sdump\-restore\.py/ nocase ascii wide
        // Description: Another tool to perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string49 = "YOLOP0wn/POSTDump" nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string50 = "YOLOP0wn/POSTDump" nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection.
        // Reference: https://github.com/YOLOP0wn/POSTDump
        $string51 = "YOLOP0wn/POSTDump" nocase ascii wide
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
