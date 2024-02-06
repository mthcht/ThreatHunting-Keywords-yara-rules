rule CmdLineSpoofer
{
    meta:
        description = "Detection patterns for the tool 'CmdLineSpoofer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CmdLineSpoofer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string1 = /\/CmdLineSpoofer\.git/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string2 = /\/CmdLineSpoofer\/.{0,1000}\.cs/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string3 = /\[\!\]\sUnable\sto\sread\sPEB\saddress\!/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string4 = /\[System\.Reflection\.Assembly\]\:\:Load\(\(Invoke\-WebRequest\s.{0,1000}\.exe.{0,1000}while\s\(\$true\)\{Start\-Sleep\s\-s\s1000\}/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string5 = /5D03EFC2\-72E9\-4410\-B147\-0A1A5C743999/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string6 = /CmdLineSpoofer\.exe/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string7 = /CmdLineSpoofer\.sln/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string8 = /CmdLineSpoofer\-master/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string9 = /plackyhacker\/CmdLineSpoofer/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string10 = /powershell\.exe\snothing\sto\ssee\shere\!\s\:\-P/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string11 = /Press\sa\skey\sto\send\sPoC\?/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string12 = /string\smaliciousCommand\s\=/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string13 = /WwBTAHkAcwB0AGUAbQAuAFIAZQBmAGwAZQBjAHQAaQBvAG4ALgBBAHMAcwBlAG0AYgBsAHkAXQA/ nocase ascii wide

    condition:
        any of them
}
