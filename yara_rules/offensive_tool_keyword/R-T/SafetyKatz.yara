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
        $string1 = /.{0,1000}\/SafetyKatz\.git.{0,1000}/ nocase ascii wide
        // Description: SafetyKatz is a combination of slightly modified version of @gentilkiwis Mimikatz project and @subtees .NET PE Loader. First. the MiniDumpWriteDump Win32 API call is used to create a minidump of LSASS to C:\Windows\Temp\debug.bin. Then @subtees PELoader is used to load a customized version of Mimikatz that runs sekurlsa::logonpasswords and sekurlsa::ekeys on the minidump file. removing the file after execution is complete
        // Reference: https://github.com/GhostPack/SafetyKatz
        $string2 = /.{0,1000}\\SafetyKatz.{0,1000}/ nocase ascii wide
        // Description: SafetyKatz is a combination of slightly modified version of @gentilkiwis Mimikatz project and @subtees .NET PE Loader. First. the MiniDumpWriteDump Win32 API call is used to create a minidump of LSASS to C:\Windows\Temp\debug.bin. Then @subtees PELoader is used to load a customized version of Mimikatz that runs sekurlsa::logonpasswords and sekurlsa::ekeys on the minidump file. removing the file after execution is complete
        // Reference: https://github.com/GhostPack/SafetyKatz
        $string3 = /.{0,1000}GhostPack\/SafetyKatz.{0,1000}/ nocase ascii wide
        // Description: SafetyKatz is a combination of slightly modified version of @gentilkiwis Mimikatz project and @subtees .NET PE Loader. First. the MiniDumpWriteDump Win32 API call is used to create a minidump of LSASS to C:\Windows\Temp\debug.bin. Then @subtees PELoader is used to load a customized version of Mimikatz that runs sekurlsa::logonpasswords and sekurlsa::ekeys on the minidump file. removing the file after execution is complete
        // Reference: https://github.com/GhostPack/SafetyKatz
        $string4 = /.{0,1000}SafetyKatz\.csproj.{0,1000}/ nocase ascii wide
        // Description: SafetyKatz is a combination of slightly modified version of @gentilkiwis Mimikatz project and @subtees .NET PE Loader. First. the MiniDumpWriteDump Win32 API call is used to create a minidump of LSASS to C:\Windows\Temp\debug.bin. Then @subtees PELoader is used to load a customized version of Mimikatz that runs sekurlsa::logonpasswords and sekurlsa::ekeys on the minidump file. removing the file after execution is complete
        // Reference: https://github.com/GhostPack/SafetyKatz
        $string5 = /.{0,1000}SafetyKatz\.exe.{0,1000}/ nocase ascii wide
        // Description: SafetyKatz is a combination of slightly modified version of @gentilkiwis Mimikatz project and @subtees .NET PE Loader. First. the MiniDumpWriteDump Win32 API call is used to create a minidump of LSASS to C:\Windows\Temp\debug.bin. Then @subtees PELoader is used to load a customized version of Mimikatz that runs sekurlsa::logonpasswords and sekurlsa::ekeys on the minidump file. removing the file after execution is complete
        // Reference: https://github.com/GhostPack/SafetyKatz
        $string6 = /.{0,1000}SafetyKatz\.sln.{0,1000}/ nocase ascii wide
        // Description: SafetyKatz is a combination of slightly modified version of @gentilkiwis Mimikatz project and @subtees .NET PE Loader. First. the MiniDumpWriteDump Win32 API call is used to create a minidump of LSASS to C:\Windows\Temp\debug.bin. Then @subtees PELoader is used to load a customized version of Mimikatz that runs sekurlsa::logonpasswords and sekurlsa::ekeys on the minidump file. removing the file after execution is complete
        // Reference: https://github.com/GhostPack/SafetyKatz
        $string7 = /.{0,1000}SafetyKatz\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
