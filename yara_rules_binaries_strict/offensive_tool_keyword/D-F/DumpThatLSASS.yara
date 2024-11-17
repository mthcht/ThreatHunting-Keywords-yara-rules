rule DumpThatLSASS
{
    meta:
        description = "Detection patterns for the tool 'DumpThatLSASS' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DumpThatLSASS"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // Reference: https://github.com/peiga/DumpThatLSASS
        $string1 = /\s1\$a\$\$\.exe/ nocase ascii wide
        // Description: Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // Reference: https://github.com/peiga/DumpThatLSASS
        $string2 = /\sl\$a\$\$Pid\s/ nocase ascii wide
        // Description: Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // Reference: https://github.com/peiga/DumpThatLSASS
        $string3 = /\/1\$a\$\$\.exe/ nocase ascii wide
        // Description: Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // Reference: https://github.com/peiga/DumpThatLSASS
        $string4 = /\/DumpThatLSASS\./ nocase ascii wide
        // Description: Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // Reference: https://github.com/peiga/DumpThatLSASS
        $string5 = /\/DumpThatLSASS\.git/ nocase ascii wide
        // Description: Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // Reference: https://github.com/peiga/DumpThatLSASS
        $string6 = /\/DumpThatLSASS\// nocase ascii wide
        // Description: Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // Reference: https://github.com/peiga/DumpThatLSASS
        $string7 = /\[\+\]\sThe\s1\$a\$\$\.exe/ nocase ascii wide
        // Description: Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // Reference: https://github.com/peiga/DumpThatLSASS
        $string8 = /\\1\$a\$\$\.exe/ nocase ascii wide
        // Description: Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // Reference: https://github.com/peiga/DumpThatLSASS
        $string9 = /\\DumpThatLSASS\./ nocase ascii wide
        // Description: Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // Reference: https://github.com/peiga/DumpThatLSASS
        $string10 = /\\DumpThatLSASS\\/ nocase ascii wide
        // Description: Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // Reference: https://github.com/peiga/DumpThatLSASS
        $string11 = /\\sysDb\-dmp/ nocase ascii wide
        // Description: Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // Reference: https://github.com/peiga/DumpThatLSASS
        $string12 = /1\$a\$\$\sDl_lmp\sin\s/ nocase ascii wide
        // Description: Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // Reference: https://github.com/peiga/DumpThatLSASS
        $string13 = /1ebee3f2cc0a98db23a6bf0af4e5dd14bd8d21a4de9cbba58d43521b0bbe1294/ nocase ascii wide
        // Description: Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // Reference: https://github.com/peiga/DumpThatLSASS
        $string14 = /64D84D51\-F462\-4A24\-85EA\-845C97238C09/ nocase ascii wide
        // Description: Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // Reference: https://github.com/peiga/DumpThatLSASS
        $string15 = /952c94381c139e9d0b212d7f854ad261827e6694eac3e17b2c606ff9f54a7e91/ nocase ascii wide
        // Description: Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // Reference: https://github.com/peiga/DumpThatLSASS
        $string16 = /Failed\sin\sm1n1dumpIT\:/ nocase ascii wide
        // Description: Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // Reference: https://github.com/peiga/DumpThatLSASS
        $string17 = /\'l\'\,\'s\'\,\'a\'\,\'s\'\,\'s\'\,\'\.\'\,\'e\'\,\'x\'\,\'e\'/ nocase ascii wide
        // Description: Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // Reference: https://github.com/peiga/DumpThatLSASS
        $string18 = /\'M\'\,\'i\'\,\'n\'\,\'i\'\,\'D\'\,\'u\'\,\'m\'\,\'p\'\,\'W\'\,\'r\'\,\'i\'\,\'t\'\,\'e\'\,\'D\'\,\'u\'\,\'m\'\,\'p\'/ nocase ascii wide
        // Description: Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // Reference: https://github.com/peiga/DumpThatLSASS
        $string19 = /peiga\/DumpThatLSASS/ nocase ascii wide
        // Description: Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // Reference: https://github.com/peiga/DumpThatLSASS
        $string20 = /\'S\'\,\'e\'\,\'D\'\,\'e\'\,\'b\'\,\'u\'\,\'g\'\,\'P\'\,\'r\'\,\'i\'\,\'v\'\,\'i\'\,\'l\'\,\'e\'\,\'g\'\,\'e\'/ nocase ascii wide
        // Description: Dumping LSASS by Unhooking MiniDumpWriteDump by getting a fresh DbgHelp.dll copy from the disk
        // Reference: https://github.com/peiga/DumpThatLSASS
        $string21 = /\'W\'\,\'i\'\,\'n\'\,\'d\'\,\'o\'\,\'w\'\,\'s\'\,\'\\\\\'\,\'S\'\,\'y\'\,\'s\'\,\'t\'\,\'e\'\,\'m\'\,\'3\'\,\'2\'/ nocase ascii wide
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
