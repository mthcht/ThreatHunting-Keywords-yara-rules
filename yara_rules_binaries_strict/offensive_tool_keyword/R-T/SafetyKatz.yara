rule SafetyKatz
{
    meta:
        description = "Detection patterns for the tool 'SafetyKatz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SafetyKatz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SafetyKatz is a combination of slightly modified version of @gentilkiwis Mimikatz project and @subtees .NET PE Loader. First. the MiniDumpWriteDump Win32 API call is used to create a minidump of LSASS to C:\Windows\Temp\debug.bin. Then @subtees PELoader is used to load a customized version of Mimikatz that runs sekurlsa::logonpasswords and sekurlsa::ekeys on the minidump file. removing the file after execution is complete
        // Reference: https://github.com/GhostPack/SafetyKatz
        $string1 = /\/SafetyKatz\.git/ nocase ascii wide
        // Description: SafetyKatz is a combination of slightly modified version of @gentilkiwis Mimikatz project and @subtees .NET PE Loader. First. the MiniDumpWriteDump Win32 API call is used to create a minidump of LSASS to C:\Windows\Temp\debug.bin. Then @subtees PELoader is used to load a customized version of Mimikatz that runs sekurlsa::logonpasswords and sekurlsa::ekeys on the minidump file. removing the file after execution is complete
        // Reference: https://github.com/GhostPack/SafetyKatz
        $string2 = /\\SafetyKatz/ nocase ascii wide
        // Description: SafetyKatz is a combination of slightly modified version of @gentilkiwis Mimikatz project and @subtees .NET PE Loader. First. the MiniDumpWriteDump Win32 API call is used to create a minidump of LSASS to C:\Windows\Temp\debug.bin. Then @subtees PELoader is used to load a customized version of Mimikatz that runs sekurlsa::logonpasswords and sekurlsa::ekeys on the minidump file. removing the file after execution is complete
        // Reference: https://github.com/GhostPack/SafetyKatz
        $string3 = /\]\sExecuting\sloaded\sMimikatz\sPE/ nocase ascii wide
        // Description: SafetyKatz is a combination of slightly modified version of @gentilkiwis Mimikatz project and @subtees .NET PE Loader. First. the MiniDumpWriteDump Win32 API call is used to create a minidump of LSASS to C:\Windows\Temp\debug.bin. Then @subtees PELoader is used to load a customized version of Mimikatz that runs sekurlsa::logonpasswords and sekurlsa::ekeys on the minidump file. removing the file after execution is complete
        // Reference: https://github.com/GhostPack/SafetyKatz
        $string4 = "387930bab7650291baada3b39dc55167c1e6f1fd2154de61f77e07bd14c8b9bc" nocase ascii wide
        // Description: SafetyKatz is a combination of slightly modified version of @gentilkiwis Mimikatz project and @subtees .NET PE Loader. First. the MiniDumpWriteDump Win32 API call is used to create a minidump of LSASS to C:\Windows\Temp\debug.bin. Then @subtees PELoader is used to load a customized version of Mimikatz that runs sekurlsa::logonpasswords and sekurlsa::ekeys on the minidump file. removing the file after execution is complete
        // Reference: https://github.com/GhostPack/SafetyKatz
        $string5 = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" nocase ascii wide
        // Description: SafetyKatz is a combination of slightly modified version of @gentilkiwis Mimikatz project and @subtees .NET PE Loader. First. the MiniDumpWriteDump Win32 API call is used to create a minidump of LSASS to C:\Windows\Temp\debug.bin. Then @subtees PELoader is used to load a customized version of Mimikatz that runs sekurlsa::logonpasswords and sekurlsa::ekeys on the minidump file. removing the file after execution is complete
        // Reference: https://github.com/GhostPack/SafetyKatz
        $string6 = "GhostPack/SafetyKatz" nocase ascii wide
        // Description: SafetyKatz is a combination of slightly modified version of @gentilkiwis Mimikatz project and @subtees .NET PE Loader. First. the MiniDumpWriteDump Win32 API call is used to create a minidump of LSASS to C:\Windows\Temp\debug.bin. Then @subtees PELoader is used to load a customized version of Mimikatz that runs sekurlsa::logonpasswords and sekurlsa::ekeys on the minidump file. removing the file after execution is complete
        // Reference: https://github.com/GhostPack/SafetyKatz
        $string7 = /SafetyKatz\.csproj/ nocase ascii wide
        // Description: SafetyKatz is a combination of slightly modified version of @gentilkiwis Mimikatz project and @subtees .NET PE Loader. First. the MiniDumpWriteDump Win32 API call is used to create a minidump of LSASS to C:\Windows\Temp\debug.bin. Then @subtees PELoader is used to load a customized version of Mimikatz that runs sekurlsa::logonpasswords and sekurlsa::ekeys on the minidump file. removing the file after execution is complete
        // Reference: https://github.com/GhostPack/SafetyKatz
        $string8 = /SafetyKatz\.exe/ nocase ascii wide
        // Description: SafetyKatz is a combination of slightly modified version of @gentilkiwis Mimikatz project and @subtees .NET PE Loader. First. the MiniDumpWriteDump Win32 API call is used to create a minidump of LSASS to C:\Windows\Temp\debug.bin. Then @subtees PELoader is used to load a customized version of Mimikatz that runs sekurlsa::logonpasswords and sekurlsa::ekeys on the minidump file. removing the file after execution is complete
        // Reference: https://github.com/GhostPack/SafetyKatz
        $string9 = /SafetyKatz\.sln/ nocase ascii wide
        // Description: SafetyKatz is a combination of slightly modified version of @gentilkiwis Mimikatz project and @subtees .NET PE Loader. First. the MiniDumpWriteDump Win32 API call is used to create a minidump of LSASS to C:\Windows\Temp\debug.bin. Then @subtees PELoader is used to load a customized version of Mimikatz that runs sekurlsa::logonpasswords and sekurlsa::ekeys on the minidump file. removing the file after execution is complete
        // Reference: https://github.com/GhostPack/SafetyKatz
        $string10 = "SafetyKatz-master" nocase ascii wide
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
