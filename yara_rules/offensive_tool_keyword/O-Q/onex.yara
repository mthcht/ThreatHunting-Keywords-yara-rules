rule onex
{
    meta:
        description = "Detection patterns for the tool 'onex' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "onex"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Onex is a package manager for hacker's. Onex manage more than 400+ hacking tools that can be installed on single click
        // Reference: https://github.com/rajkumardusad/onex
        $string1 = /\/onex\.git/ nocase ascii wide
        // Description: C# implementation of mimikatz/pypykatz minidump functionality to get credentials from LSASS dumps
        // Reference: https://github.com/cube0x0/MiniDump
        $string2 = /cube0x0\/MiniDump/ nocase ascii wide
        // Description: C# implementation of mimikatz/pypykatz minidump functionality to get credentials from LSASS dumps
        // Reference: https://github.com/cube0x0/MiniDump
        $string3 = /minidump\..{0,1000}\slsass\.dmp/ nocase ascii wide
        // Description: C# implementation of mimikatz/pypykatz minidump functionality to get credentials from LSASS dumps
        // Reference: https://github.com/cube0x0/MiniDump
        $string4 = /procdump.{0,1000}\slsass\.exe\s.{0,1000}\.dmp/ nocase ascii wide
        // Description: Onex is a package manager for hacker's. Onex manage more than 400+ hacking tools that can be installed on single click
        // Reference: https://github.com/rajkumardusad/onex
        $string5 = /rajkumardusad\/onex/ nocase ascii wide
        // Description: Onex is a package manager for hacker's. Onex manage more than 400+ hacking tools that can be installed on single click
        // Reference: https://github.com/rajkumardusad/onex
        $string6 = /onex\sinstall\s/ nocase ascii wide

    condition:
        any of them
}
