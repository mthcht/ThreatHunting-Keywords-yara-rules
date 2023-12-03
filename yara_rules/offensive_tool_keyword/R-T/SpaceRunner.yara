rule SpaceRunner
{
    meta:
        description = "Detection patterns for the tool 'SpaceRunner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpaceRunner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string1 = /.{0,1000}\s\-f\sFind\-AllVulns.{0,1000}/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string2 = /.{0,1000}\s\-f\sFind\-PathDLLHijack.{0,1000}/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string3 = /.{0,1000}\s\-f\sGet\-DomainGroupMember.{0,1000}\s\-a\s.{0,1000}\-Identity\s.{0,1000}admin.{0,1000}\s\-Recurse.{0,1000}/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string4 = /.{0,1000}\s\-f\sInvoke\-Inveigh.{0,1000}/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string5 = /.{0,1000}\/out:spacerunner\.exe.{0,1000}/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string6 = /.{0,1000}\/SpaceRunner\.git.{0,1000}/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string7 = /.{0,1000}\/target:exe\sspacerunner\.cs.{0,1000}/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string8 = /.{0,1000}\[\+\]\sGenerating\sbase64\sencoded\sPowerShell\sscript.{0,1000}/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string9 = /.{0,1000}\\inveigh\.exe.{0,1000}/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string10 = /.{0,1000}\\Powerup\.exe.{0,1000}/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string11 = /.{0,1000}\\Powerview\.exe.{0,1000}/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string12 = /.{0,1000}\\sherlock\.exe.{0,1000}/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string13 = /.{0,1000}beacon\.ps1.{0,1000}beacon\.exe.{0,1000}/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string14 = /.{0,1000}Mr\-B0b\/SpaceRunner.{0,1000}/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string15 = /.{0,1000}spacerunner\.exe\s\-i\s.{0,1000}\.ps1.{0,1000}\s\-o\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string16 = /.{0,1000}SpaceRunner\-master\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
