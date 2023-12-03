rule rwxfinder
{
    meta:
        description = "Detection patterns for the tool 'rwxfinder' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rwxfinder"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The program uses the Windows API functions to traverse through directories and locate DLL files with RWX section
        // Reference: https://github.com/pwnsauc3/RWXFinder
        $string1 = /.{0,1000}\/RWXfinder\.git.{0,1000}/ nocase ascii wide
        // Description: The program uses the Windows API functions to traverse through directories and locate DLL files with RWX section
        // Reference: https://github.com/pwnsauc3/RWXFinder
        $string2 = /.{0,1000}pwnsauc3\/RWXFinder.{0,1000}/ nocase ascii wide
        // Description: The program uses the Windows API functions to traverse through directories and locate DLL files with RWX section
        // Reference: https://github.com/pwnsauc3/RWXFinder
        $string3 = /.{0,1000}rwxfinder\..{0,1000}/ nocase ascii wide
        // Description: The program uses the Windows API functions to traverse through directories and locate DLL files with RWX section
        // Reference: https://github.com/pwnsauc3/RWXFinder
        $string4 = /.{0,1000}RWXfinder\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
