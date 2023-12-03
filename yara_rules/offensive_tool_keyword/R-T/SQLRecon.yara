rule SQLRecon
{
    meta:
        description = "Detection patterns for the tool 'SQLRecon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SQLRecon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A C# MS SQL toolkit designed for offensive reconnaissance and post-exploitation
        // Reference: https://github.com/skahwah/SQLRecon
        $string1 = /.{0,1000}\s\-m\slagentcmd\s.{0,1000}powershell\s.{0,1000}/ nocase ascii wide
        // Description: A C# MS SQL toolkit designed for offensive reconnaissance and post-exploitation
        // Reference: https://github.com/skahwah/SQLRecon
        $string2 = /.{0,1000}\s\-m\solecmd\s\-o\s.{0,1000}powershell\s.{0,1000}/ nocase ascii wide
        // Description: A C# MS SQL toolkit designed for offensive reconnaissance and post-exploitation
        // Reference: https://github.com/skahwah/SQLRecon
        $string3 = /.{0,1000}\/SQLRecon.{0,1000}/ nocase ascii wide
        // Description: A C# MS SQL toolkit designed for offensive reconnaissance and post-exploitation
        // Reference: https://github.com/skahwah/SQLRecon
        $string4 = /.{0,1000}\\SQLRecon.{0,1000}/ nocase ascii wide
        // Description: A C# MS SQL toolkit designed for offensive reconnaissance and post-exploitation
        // Reference: https://github.com/skahwah/SQLRecon
        $string5 = /.{0,1000}\\temp\\hollow\.dll.{0,1000}/ nocase ascii wide
        // Description: A C# MS SQL toolkit designed for offensive reconnaissance and post-exploitation
        // Reference: https://github.com/skahwah/SQLRecon
        $string6 = /.{0,1000}SQLRecon\.exe.{0,1000}/ nocase ascii wide
        // Description: A C# MS SQL toolkit designed for offensive reconnaissance and post-exploitation
        // Reference: https://github.com/skahwah/SQLRecon
        $string7 = /.{0,1000}SQLRecon\.git.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
