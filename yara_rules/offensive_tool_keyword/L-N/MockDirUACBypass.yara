rule MockDirUACBypass
{
    meta:
        description = "Detection patterns for the tool 'MockDirUACBypass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MockDirUACBypass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Creates a mock trusted directory C:\Windows \System32\ and moves an auto-elevating Windows executable into the mock directory. A user-supplied DLL which exports the appropriate functions is dropped and when the executable is run - the DLL is loaded and run as high integrity.
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/MockDirUACBypass
        $string1 = /\[\+\]\sAttempting\sto\scall\sthe\starget\sEXE\sfrom\sthe\smock\sdirectory/ nocase ascii wide
        // Description: Creates a mock trusted directory C:\Windows \System32\ and moves an auto-elevating Windows executable into the mock directory. A user-supplied DLL which exports the appropriate functions is dropped and when the executable is run - the DLL is loaded and run as high integrity.
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/MockDirUACBypass
        $string2 = /\[\+\]\sCreating\smock\sdirectories/ nocase ascii wide
        // Description: Creates a mock trusted directory C:\Windows \System32\ and moves an auto-elevating Windows executable into the mock directory. A user-supplied DLL which exports the appropriate functions is dropped and when the executable is run - the DLL is loaded and run as high integrity.
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/MockDirUACBypass
        $string3 = /hijackDll.{0,1000}WINMM\.dll/ nocase ascii wide
        // Description: Creates a mock trusted directory C:\Windows \System32\ and moves an auto-elevating Windows executable into the mock directory. A user-supplied DLL which exports the appropriate functions is dropped and when the executable is run - the DLL is loaded and run as high integrity.
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/MockDirUACBypass
        $string4 = /MockDirUACBypass/ nocase ascii wide

    condition:
        any of them
}
