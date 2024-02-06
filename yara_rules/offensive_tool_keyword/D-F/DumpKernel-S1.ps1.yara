rule DumpKernel_S1_ps1
{
    meta:
        description = "Detection patterns for the tool 'DumpKernel-S1.ps1' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DumpKernel-S1.ps1"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SentinelHelper to perform a live kernel dump in a Windows environment
        // Reference: https://gist.github.com/adamsvoboda/8f29e09d74b73e1dec3f9049c4358e80
        $string1 = /C\:\\kernel\.dmp/ nocase ascii wide
        // Description: SentinelHelper to perform a live kernel dump in a Windows environment
        // Reference: https://gist.github.com/adamsvoboda/8f29e09d74b73e1dec3f9049c4358e80
        $string2 = /DumpKernel\-S1\.ps1/ nocase ascii wide
        // Description: SentinelHelper to perform a live kernel dump in a Windows environment
        // Reference: https://gist.github.com/adamsvoboda/8f29e09d74b73e1dec3f9049c4358e80
        $string3 = /Trying\sto\sdump\skernel\sto\sC\:/ nocase ascii wide

    condition:
        any of them
}
