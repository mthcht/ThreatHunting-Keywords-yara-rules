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
        $string1 = /.{0,1000}\/CmdLineSpoofer\.git.{0,1000}/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string2 = /.{0,1000}\/CmdLineSpoofer\/.{0,1000}\.cs.{0,1000}/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string3 = /.{0,1000}\[\!\]\sUnable\sto\sread\sPEB\saddress\!.{0,1000}/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string4 = /.{0,1000}\[System\.Reflection\.Assembly\]::Load\(\(Invoke\-WebRequest\s.{0,1000}\.exe.{0,1000}while\s\(\$true\){Start\-Sleep\s\-s\s1000}.{0,1000}/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string5 = /.{0,1000}5D03EFC2\-72E9\-4410\-B147\-0A1A5C743999.{0,1000}/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string6 = /.{0,1000}CmdLineSpoofer\.exe.{0,1000}/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string7 = /.{0,1000}CmdLineSpoofer\.sln.{0,1000}/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string8 = /.{0,1000}CmdLineSpoofer\-master.{0,1000}/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string9 = /.{0,1000}plackyhacker\/CmdLineSpoofer.{0,1000}/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string10 = /.{0,1000}powershell\.exe\snothing\sto\ssee\shere\!\s:\-P.{0,1000}/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string11 = /.{0,1000}Press\sa\skey\sto\send\sPoC\?.{0,1000}/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string12 = /.{0,1000}string\smaliciousCommand\s\=.{0,1000}/ nocase ascii wide
        // Description: How to spoof the command line when spawning a new process from C#
        // Reference: https://github.com/plackyhacker/CmdLineSpoofer
        $string13 = /.{0,1000}WwBTAHkAcwB0AGUAbQAuAFIAZQBmAGwAZQBjAHQAaQBvAG4ALgBBAHMAcwBlAG0AYgBsAHkAXQA.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
