rule TrickDump
{
    meta:
        description = "Detection patterns for the tool 'TrickDump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TrickDump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string1 = /\/TrickDump\.git/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string2 = /\\Barrel\.exe\sdebugproc/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string3 = /\\Lock\.exe\sdisk/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string4 = /\\Shock\.exe\sknowndlls/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string5 = /\\temp\\trick\.zip.{0,100}\.json/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string6 = /\\TrickDump\.sln/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string7 = /\\TrickDump\-main/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string8 = /\>Shock\.exe\</ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string9 = /\>Trick\.exe\</ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string10 = "12bc134420da64f0ff3a93d3a1ca6376677ae9c0494b545173bf20e45787e873" nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string11 = "2010807d09f45f949a2e24615d58a15d8914e09f9988aa8fd7c863c7e5434aa8" nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string12 = "4957a3e8d46d84698c5987e2c45bc2705865ac8cf742218c574de4cee69da080" nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string13 = "9E9BB94C-1FBE-4D0B-83B7-E42C83FC5D45" nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string14 = "B92B6B67-C7C8-4548-85EE-A215D74C000D" nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string15 = "by @ricardojoserf" nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string16 = "C666C98C-84C3-4A5A-A73B-2FC711CFCB7F" nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string17 = "d2888f1714566be066719ca2bcbe9e5948a002a7f12070397b306e96442c26aa" nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string18 = "D8FC3807-CEAA-4F6A-9C8F-CC96F99D1F04" nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string19 = "e4bc4fc4b8f65caedc7302900804da6af5689a7f3a03b31ae62433b24f393568" nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string20 = /go\sbuild\slock\.go\s\&\&\sgo\sbuild\sshock\.go\s\&\&\sgo\sbuild\sbarrel\.go/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string21 = /go\srun\slock\.go\s\-o\sdisk/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string22 = /go\srun\sshock\.go\s\-o\sknwondlls/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string23 = /http\:\/\/127\.0\.0\.1\/ntdll\.dll/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string24 = /nuitka\s\-\-onefile\sbarrel\.py/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string25 = /nuitka\s\-\-onefile\slock\.py/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string26 = /nuitka\s\-\-onefile\sshock\.py/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string27 = /pyinstaller\s\-F\sbarrel\.py/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string28 = /pyinstaller\s\-F\slock\.py/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string29 = /pyinstaller\s\-F\sshock\.py/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string30 = /python\sbarrel\.go\s\-o\sdebugproc/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string31 = /python\sbarrel\.py\s\-o\sdebugproc/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string32 = /python\screate_dump\.py\s/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string33 = /python\slock\.py\s\-o\sdisk/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string34 = /python\sshock\.py\s\-o\sknwondlls/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string35 = /python\.exe.{0,100}\screate_dump\.py\s/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string36 = /python3\screate_dump\.py\s/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string37 = /python3\.exe.{0,100}\screate_dump\.py\s/ nocase ascii wide
        // Description: Dump lsass using only NTAPIS running 3 programs to create 3 JSON and 1 ZIP file and generate the Minidump later!
        // Reference: https://github.com/ricardojoserf/TrickDump
        $string38 = "ricardojoserf/TrickDump" nocase ascii wide
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
