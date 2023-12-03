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
        $string1 = /.{0,1000}\/onex\.git.{0,1000}/ nocase ascii wide
        // Description: C# implementation of mimikatz/pypykatz minidump functionality to get credentials from LSASS dumps
        // Reference: https://github.com/cube0x0/MiniDump
        $string2 = /.{0,1000}cube0x0\/MiniDump.{0,1000}/ nocase ascii wide
        // Description: C# implementation of mimikatz/pypykatz minidump functionality to get credentials from LSASS dumps
        // Reference: https://github.com/cube0x0/MiniDump
        $string3 = /.{0,1000}minidump\..{0,1000}\slsass\.dmp.{0,1000}/ nocase ascii wide
        // Description: C# implementation of mimikatz/pypykatz minidump functionality to get credentials from LSASS dumps
        // Reference: https://github.com/cube0x0/MiniDump
        $string4 = /.{0,1000}procdump.{0,1000}\slsass\.exe\s.{0,1000}\.dmp.{0,1000}/ nocase ascii wide
        // Description: Onex is a package manager for hacker's. Onex manage more than 400+ hacking tools that can be installed on single click
        // Reference: https://github.com/rajkumardusad/onex
        $string5 = /.{0,1000}rajkumardusad\/onex.{0,1000}/ nocase ascii wide
        // Description: Onex is a package manager for hacker's. Onex manage more than 400+ hacking tools that can be installed on single click
        // Reference: https://github.com/rajkumardusad/onex
        $string6 = /onex\sinstall\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
