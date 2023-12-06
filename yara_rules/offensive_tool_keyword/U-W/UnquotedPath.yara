rule UnquotedPath
{
    meta:
        description = "Detection patterns for the tool 'UnquotedPath' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UnquotedPath"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Outputs a list of unquoted service paths that aren't in System32/SysWow64 to plant a PE into
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/UnquotedPath
        $string1 = /master\/UnquotedPath/ nocase ascii wide
        // Description: Outputs a list of unquoted service paths that aren't in System32/SysWow64 to plant a PE into
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/UnquotedPath
        $string2 = /UnquotedPath\.csproj/ nocase ascii wide
        // Description: Outputs a list of unquoted service paths that aren't in System32/SysWow64 to plant a PE into
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/UnquotedPath
        $string3 = /UnquotedPath\.exe/ nocase ascii wide

    condition:
        any of them
}
