rule PerfExec
{
    meta:
        description = "Detection patterns for the tool 'PerfExec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PerfExec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PerfExec - an example performance dll that will run CMD.exe and a .NET assembly that will execute the DLL or gather performance data locally or remotely.
        // Reference: https://github.com/0xthirteen/PerfExec
        $string1 = /\sdiagrun\=true\sservice\=DNS.{0,1000}\sdllpath\=.{0,1000}\.dll.{0,1000}\scomputername\=/ nocase ascii wide
        // Description: PerfExec - an example performance dll that will run CMD.exe and a .NET assembly that will execute the DLL or gather performance data locally or remotely.
        // Reference: https://github.com/0xthirteen/PerfExec
        $string2 = /\swmirun\=true\sdllpath\=.{0,1000}\.dll.{0,1000}\scomputername\=/ nocase ascii wide
        // Description: PerfExec - an example performance dll that will run CMD.exe and a .NET assembly that will execute the DLL or gather performance data locally or remotely.
        // Reference: https://github.com/0xthirteen/PerfExec
        $string3 = /\\PerfExec\.exe/ nocase ascii wide
        // Description: PerfExec - an example performance dll that will run CMD.exe and a .NET assembly that will execute the DLL or gather performance data locally or remotely.
        // Reference: https://github.com/0xthirteen/PerfExec
        $string4 = /0xthirteen\/PerfExec/ nocase ascii wide
        // Description: PerfExec - an example performance dll that will run CMD.exe and a .NET assembly that will execute the DLL or gather performance data locally or remotely.
        // Reference: https://github.com/0xthirteen/PerfExec
        $string5 = /PerfExec\.sln/ nocase ascii wide
        // Description: PerfExec - an example performance dll that will run CMD.exe and a .NET assembly that will execute the DLL or gather performance data locally or remotely.
        // Reference: https://github.com/0xthirteen/PerfExec
        $string6 = /PerfExec\-main\.zip/ nocase ascii wide

    condition:
        any of them
}
