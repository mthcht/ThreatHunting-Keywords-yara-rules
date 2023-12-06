rule shhmon
{
    meta:
        description = "Detection patterns for the tool 'shhmon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shhmon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Neutering Sysmon via driver unload
        // Reference: https://github.com/matterpreter/Shhmon
        $string1 = /\/Shhmon\// nocase ascii wide
        // Description: Neutering Sysmon via driver unload
        // Reference: https://github.com/matterpreter/Shhmon
        $string2 = /\\Shhmon\./ nocase ascii wide
        // Description: Neutering Sysmon via driver unload
        // Reference: https://github.com/matterpreter/Shhmon
        $string3 = /matterpreter\/Shhmon/ nocase ascii wide
        // Description: Neutering Sysmon via driver unload
        // Reference: https://github.com/matterpreter/Shhmon
        $string4 = /Shhmon\.csproj/ nocase ascii wide
        // Description: Neutering Sysmon via driver unload
        // Reference: https://github.com/matterpreter/Shhmon
        $string5 = /Shhmon\.exe/ nocase ascii wide
        // Description: Neutering Sysmon via driver unload
        // Reference: https://github.com/matterpreter/Shhmon
        $string6 = /Shhmon\.git/ nocase ascii wide
        // Description: Neutering Sysmon via driver unload
        // Reference: https://github.com/matterpreter/Shhmon
        $string7 = /sshmon.{0,1000}hunt/ nocase ascii wide
        // Description: Neutering Sysmon via driver unload
        // Reference: https://github.com/matterpreter/Shhmon
        $string8 = /sshmon.{0,1000}kill/ nocase ascii wide

    condition:
        any of them
}
