rule PhantomService
{
    meta:
        description = "Detection patterns for the tool 'PhantomService' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PhantomService"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Searches for and removes non-ASCII services that can't be easily removed by built-in Windows tools
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/PhantomService
        $string1 = /\/master\/PhantomService\// nocase ascii wide
        // Description: Searches for and removes non-ASCII services that can't be easily removed by built-in Windows tools
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/PhantomService
        $string2 = /\]\sFound\snon\-ASCII\sservice\:\s/ nocase ascii wide
        // Description: Searches for and removes non-ASCII services that can't be easily removed by built-in Windows tools
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/PhantomService
        $string3 = /PhantomService\.csproj/ nocase ascii wide
        // Description: Searches for and removes non-ASCII services that can't be easily removed by built-in Windows tools
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/PhantomService
        $string4 = /PhantomService\.exe/ nocase ascii wide

    condition:
        any of them
}
