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
        $string1 = /\s\-f\sFind\-AllVulns/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string2 = /\s\-f\sFind\-PathDLLHijack/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string3 = /\s\-f\sGet\-DomainGroupMember.{0,1000}\s\-a\s.{0,1000}\-Identity\s.{0,1000}admin.{0,1000}\s\-Recurse/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string4 = /\s\-f\sInvoke\-Inveigh/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string5 = /\/out\:spacerunner\.exe/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string6 = /\/SpaceRunner\.git/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string7 = /\/target\:exe\sspacerunner\.cs/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string8 = /\[\+\]\sGenerating\sbase64\sencoded\sPowerShell\sscript/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string9 = /\\inveigh\.exe/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string10 = /\\Powerup\.exe/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string11 = /\\Powerview\.exe/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string12 = /\\sherlock\.exe/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string13 = /beacon\.ps1.{0,1000}beacon\.exe/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string14 = /Mr\-B0b\/SpaceRunner/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string15 = /spacerunner\.exe\s\-i\s.{0,1000}\.ps1.{0,1000}\s\-o\s.{0,1000}\.exe/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string16 = /SpaceRunner\-master\.zip/ nocase ascii wide

    condition:
        any of them
}
