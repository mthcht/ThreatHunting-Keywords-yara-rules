rule OffensiveCpp
{
    meta:
        description = "Detection patterns for the tool 'OffensiveCpp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OffensiveCpp"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string1 = /\sadmin_persistence_winlogon\.c/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string2 = /\sSMB_Staging\.c/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string3 = /\suser_persistence_run\.c/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string4 = /\/admin_persistence_winlogon\.c/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string5 = /\/OffensiveCpp\.git/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string6 = /\/thread\-injector\.exe/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string7 = /\/user_persistence_run\.c/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string8 = /\\\\\\\\.{0,100}\\\\share\\\\test\.bin/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string9 = /\\admin_persistence_winlogon/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string10 = /\\Evasion\\Sandbox\sEvasion\\.{0,100}\.c/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string11 = /\\Evasion\\Sandbox\sEvasion\\.{0,100}\.exe/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string12 = /\\OffensiveCpp\\/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string13 = /\\OffensiveCpp\-main/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string14 = /\\Shellcode\sExecution\\CertEnumSystemStore\\/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string15 = /\\Shellcode\sExecution\\Enum/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string16 = /\\SMB_Staging\.c/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string17 = /\\thread\-injector\.exe/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string18 = /\\user_persistence_run\.c/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string19 = /\]\sInjecting\sinto\sremote\sprocess\susing\sdirect\ssyscalls/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string20 = /\]\sInjecting\sinto\sremote\sprocess\susing\sdirect\ssyscalls/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string21 = /a8944d1ff8c72e68ca1bb55dad84aae6cb7d4cbcc92d442dc8497c8949a96adc/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string22 = /d3366dc09c1ec4e93c9a40f4de0f96088786b6fb44b3fafb3d648a4b6342b596/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string23 = /fbb4a1a49a0683247e83da8d2ccd4bdab51516a0a5cacbf6ff759213792e58e2/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string24 = /If\sno\sprocess\sprovided\,\sit\swill\sattempt\sto\sinject\sinto\sexplorer\.exe/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string25 = /JohnWoodman\/stealthInjector/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string26 = /lsecqt\/OffensiveCpp/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string27 = /No\ssandbox\-indicative\sDLLs\swere\sdiscovered\sloaded\sin\sany\saccessible\srunning\sprocess/ nocase ascii wide
        // Description: C/C++ snippets that can be handy in specific offensive scenarios
        // Reference: https://github.com/lsecqt/OffensiveCpp
        $string28 = /thread\-injector\.exe\s/ nocase ascii wide
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
