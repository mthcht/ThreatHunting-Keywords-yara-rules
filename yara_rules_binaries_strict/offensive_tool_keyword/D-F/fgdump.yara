rule fgdump
{
    meta:
        description = "Detection patterns for the tool 'fgdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fgdump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://github.com/ihamburglar/fgdump
        $string1 = /\/fgdump\.git/ nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://github.com/ihamburglar/fgdump
        $string2 = /\\killmsas\.exe/ nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://github.com/ihamburglar/fgdump
        $string3 = /\\pipe\\\\cachedumppipe/ nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://github.com/ihamburglar/fgdump
        $string4 = /\\pipe\\cachedumppipe/ nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://github.com/ihamburglar/fgdump
        $string5 = "0f340b471ef34c69f5413540acd3095c829ffc4df38764e703345eb5e5020301" nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://github.com/ihamburglar/fgdump
        $string6 = "1526febbe627085a24dd59eefa206fddd88326d78beb00b6630989cc13526733" nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://github.com/ihamburglar/fgdump
        $string7 = "7A87DEAE-7B94-4986-9294-BD69B12A9732" nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://github.com/ihamburglar/fgdump
        $string8 = "97b39ac28794a7610ed83ad65e28c605397ea7be878109c35228c126d43e2f46" nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://github.com/ihamburglar/fgdump
        $string9 = "a96e22322b009000a8b0b8cf7229f4e40c36b260f1076f1c225c12a43613c405" nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://github.com/ihamburglar/fgdump
        $string10 = "CacheDump service successfully installed" nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://gitlab.com/kalilinux/packages/windows-binaries/-/tree/kali/master/fgdump
        $string11 = /cachedump\.exe/ nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://gitlab.com/kalilinux/packages/windows-binaries/-/tree/kali/master/fgdump
        $string12 = /cachedump64\.exe/ nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://github.com/ihamburglar/fgdump
        $string13 = "CD8FD3D4-15FD-489C-A334-91F551B98022" nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://github.com/ihamburglar/fgdump
        $string14 = "e0327c1218fd3723e20acc780e20135f41abca35c35e0f97f7eccac265f4f44e" nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://github.com/ihamburglar/fgdump
        $string15 = "E1D50AB4-E1CD-4C31-AED5-E957D2E6B01F" nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://github.com/ihamburglar/fgdump
        $string16 = "efa66f6391ec471ca52cd053159c8a8778f11f921da14e6daf76387f8c9afcd5" nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://gitlab.com/kalilinux/packages/windows-binaries/-/tree/kali/master/fgdump
        $string17 = /fgdump\.exe/ nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://github.com/ihamburglar/fgdump
        $string18 = "fgexec -c " nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://gitlab.com/kalilinux/packages/windows-binaries/-/tree/kali/master/fgdump
        $string19 = /fgexec\.exe/ nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://github.com/ihamburglar/fgdump
        $string20 = "ihamburglar/fgdump" nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://github.com/ihamburglar/fgdump
        $string21 = /Kill\sCacheDump\sservice\s\(shouldn\'t\sbe\sused\)/ nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://gitlab.com/kalilinux/packages/windows-binaries/-/tree/kali/master/fgdump
        $string22 = /pstgdump\.exe/ nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://gitlab.com/kalilinux/packages/windows-binaries/-/tree/kali/master/fgdump
        $string23 = /pwdump\.exe/ nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://github.com/ihamburglar/fgdump
        $string24 = "pwdump/cachedump" nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://gitlab.com/kalilinux/packages/windows-binaries/-/tree/kali/master/fgdump
        $string25 = /servpw\.exe/ nocase ascii wide
        // Description: A utility for dumping passwords on Windows NT/2000/XP/2003 machines
        // Reference: https://gitlab.com/kalilinux/packages/windows-binaries/-/tree/kali/master/fgdump
        $string26 = /servpw64\.exe/ nocase ascii wide
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
