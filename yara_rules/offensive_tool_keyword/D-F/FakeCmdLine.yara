rule FakeCmdLine
{
    meta:
        description = "Detection patterns for the tool 'FakeCmdLine' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FakeCmdLine"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Simple demonstration (C source code and compiled .exe) of a less-known (but documented) behavior of CreateProcess() function. Effectively you can put any string into the child process Command Line field.
        // Reference: https://github.com/gtworek/PSBits/tree/master/FakeCmdLine
        $string1 = /.{0,1000}\/FakeCmdLine.{0,1000}/ nocase ascii wide
        // Description: Simple demonstration (C source code and compiled .exe) of a less-known (but documented) behavior of CreateProcess() function. Effectively you can put any string into the child process Command Line field.
        // Reference: https://github.com/gtworek/PSBits/tree/master/FakeCmdLine
        $string2 = /.{0,1000}\\FakeCmdLine.{0,1000}/ nocase ascii wide
        // Description: Simple demonstration (C source code and compiled .exe) of a less-known (but documented) behavior of CreateProcess() function. Effectively you can put any string into the child process Command Line field.
        // Reference: https://github.com/gtworek/PSBits/tree/master/FakeCmdLine
        $string3 = /.{0,1000}ExeToLaunch\sStringToBePutAsCmdline.{0,1000}/ nocase ascii wide
        // Description: Simple demonstration (C source code and compiled .exe) of a less-known (but documented) behavior of CreateProcess() function. Effectively you can put any string into the child process Command Line field.
        // Reference: https://github.com/gtworek/PSBits/tree/master/FakeCmdLine
        $string4 = /.{0,1000}FakeCmdLine\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}
