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
        $string1 = /.{0,1000}\/Shhmon\/.{0,1000}/ nocase ascii wide
        // Description: Neutering Sysmon via driver unload
        // Reference: https://github.com/matterpreter/Shhmon
        $string2 = /.{0,1000}\\Shhmon\..{0,1000}/ nocase ascii wide
        // Description: Neutering Sysmon via driver unload
        // Reference: https://github.com/matterpreter/Shhmon
        $string3 = /.{0,1000}matterpreter\/Shhmon.{0,1000}/ nocase ascii wide
        // Description: Neutering Sysmon via driver unload
        // Reference: https://github.com/matterpreter/Shhmon
        $string4 = /.{0,1000}Shhmon\.csproj.{0,1000}/ nocase ascii wide
        // Description: Neutering Sysmon via driver unload
        // Reference: https://github.com/matterpreter/Shhmon
        $string5 = /.{0,1000}Shhmon\.exe.{0,1000}/ nocase ascii wide
        // Description: Neutering Sysmon via driver unload
        // Reference: https://github.com/matterpreter/Shhmon
        $string6 = /.{0,1000}Shhmon\.git.{0,1000}/ nocase ascii wide
        // Description: Neutering Sysmon via driver unload
        // Reference: https://github.com/matterpreter/Shhmon
        $string7 = /.{0,1000}sshmon.{0,1000}hunt.{0,1000}/ nocase ascii wide
        // Description: Neutering Sysmon via driver unload
        // Reference: https://github.com/matterpreter/Shhmon
        $string8 = /.{0,1000}sshmon.{0,1000}kill.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
