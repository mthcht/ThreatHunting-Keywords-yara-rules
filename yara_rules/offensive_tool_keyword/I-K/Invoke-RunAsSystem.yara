rule Invoke_RunAsSystem
{
    meta:
        description = "Detection patterns for the tool 'Invoke-RunAsSystem' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-RunAsSystem"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A simple script to elevate current session to SYSTEM (needs to be run as Administrator)
        // Reference: https://github.com/Leo4j/Invoke-RunAsSystem
        $string1 = /\/Invoke\-RunAsSystem\.git/ nocase ascii wide
        // Description: A simple script to elevate current session to SYSTEM (needs to be run as Administrator)
        // Reference: https://github.com/Leo4j/Invoke-RunAsSystem
        $string2 = /5f685def3707cb4737e0e520d86b05a0c7c7d973c9b0d26b89dddd9f1d615404/ nocase ascii wide
        // Description: A simple script to elevate current session to SYSTEM (needs to be run as Administrator)
        // Reference: https://github.com/Leo4j/Invoke-RunAsSystem
        $string3 = /Invoke\-RunAsSystem\.ps1/ nocase ascii wide
        // Description: A simple script to elevate current session to SYSTEM (needs to be run as Administrator)
        // Reference: https://github.com/Leo4j/Invoke-RunAsSystem
        $string4 = /Leo4j\/Invoke\-RunAsSystem/ nocase ascii wide

    condition:
        any of them
}
