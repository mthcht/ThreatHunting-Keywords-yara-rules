rule SpaceRunner
{
    meta:
        description = "Detection patterns for the tool 'SpaceRunner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpaceRunner"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string1 = /\/spacerunner\.exe/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string2 = /\\spacerunner\.exe/ nocase ascii wide

    condition:
        any of them
}
