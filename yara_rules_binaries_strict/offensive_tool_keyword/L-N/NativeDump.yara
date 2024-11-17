rule NativeDump
{
    meta:
        description = "Detection patterns for the tool 'NativeDump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NativeDump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string1 = /\sNativeDump\.exe/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string2 = /\/Lsass_Shtinkering\.cpp/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string3 = /\/Lsass_Shtinkering\.exe/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string4 = /\/Lsass\-Shtinkering\.git/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string5 = /\/NativeDump\.exe/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string6 = /\/NativeDump\.git/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string7 = /\\Lsass_Shtinkering\.cpp/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string8 = /\\LSASS_Shtinkering\.sln/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string9 = /\\LSASS_Shtinkering\\/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string10 = /\\Lsass\-Shtinkering\-main/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string11 = /\\NativeDump\.csproj/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string12 = /\\NativeDump\.exe/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string13 = /\\NativeDump\.sln/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string14 = /\\NativeDump\\Program\.cs/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string15 = /0DF612AE\-47D8\-422C\-B0C5\-0727EA60784F/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string16 = /254389e27339fd66920dd72f3ad07fe2e220f6b0cbea8032cf0b1d8285a7b098/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string17 = /476FC126\-239F\-4D58\-8389\-E1C0E93C2C5E/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string18 = /5571bc0232f7f7911042503b2a2224ad420788d999eb819257a00943928a56bb/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string19 = /5ccafa7f7b00774dd423a64460ef3d1c551ee95f076107cb8353f6271819f4d7/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string20 = /9b7e60f60ab5e2680554d392c3e8a84b9e367a6e452eaab011d1eef963aad894/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string21 = /deepinstinct\/Lsass\-Shtinkering/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string22 = /ef9c57ffe31d8ceeb51daeac466dc8835807ab7d9fd3ff05ada8ce9b4836d924/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string23 = /NativeDump\.exe\s.{0,100}\.dmp/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string24 = /process\smust\srun\sas\sNT\sAUTHORITY\\\\SYSTEM\sto\sdump\slsass\smemory/ nocase ascii wide
        // Description: Dump lsass using only Native APIs by hand-crafting Minidump files (without MinidumpWriteDump!)
        // Reference: https://github.com/ricardojoserf/NativeDump
        $string25 = /ricardojoserf\/NativeDump/ nocase ascii wide
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
