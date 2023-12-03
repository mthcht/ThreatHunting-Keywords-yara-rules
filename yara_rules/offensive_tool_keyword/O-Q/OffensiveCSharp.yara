rule OffensiveCSharp
{
    meta:
        description = "Detection patterns for the tool 'OffensiveCSharp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OffensiveCSharp"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Collection of Offensive C# Tooling
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master
        $string1 = /.{0,1000}\/OffensiveCSharp\.git.{0,1000}/ nocase ascii wide
        // Description: Collection of Offensive C# Tooling
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master
        $string2 = /.{0,1000}\/OffensiveCSharp\/.{0,1000}/ nocase ascii wide
        // Description: Collection of Offensive C# Tooling
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master
        $string3 = /.{0,1000}\\OffensiveCSharp\\.{0,1000}/ nocase ascii wide
        // Description: Collection of Offensive C# Tooling
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master
        $string4 = /.{0,1000}OffensiveCSharp\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
