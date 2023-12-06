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
        $string1 = /\s\-m\slagentcmd\s.{0,1000}powershell\s/ nocase ascii wide
        // Description: A C# MS SQL toolkit designed for offensive reconnaissance and post-exploitation
        // Reference: https://github.com/skahwah/SQLRecon
        $string2 = /\s\-m\solecmd\s\-o\s.{0,1000}powershell\s/ nocase ascii wide
        // Description: A C# MS SQL toolkit designed for offensive reconnaissance and post-exploitation
        // Reference: https://github.com/skahwah/SQLRecon
        $string3 = /\/SQLRecon/ nocase ascii wide
        // Description: A C# MS SQL toolkit designed for offensive reconnaissance and post-exploitation
        // Reference: https://github.com/skahwah/SQLRecon
        $string4 = /\\SQLRecon/ nocase ascii wide
        // Description: A C# MS SQL toolkit designed for offensive reconnaissance and post-exploitation
        // Reference: https://github.com/skahwah/SQLRecon
        $string5 = /\\temp\\hollow\.dll/ nocase ascii wide
        // Description: A C# MS SQL toolkit designed for offensive reconnaissance and post-exploitation
        // Reference: https://github.com/skahwah/SQLRecon
        $string6 = /SQLRecon\.exe/ nocase ascii wide
        // Description: A C# MS SQL toolkit designed for offensive reconnaissance and post-exploitation
        // Reference: https://github.com/skahwah/SQLRecon
        $string7 = /SQLRecon\.git/ nocase ascii wide

    condition:
        any of them
}
