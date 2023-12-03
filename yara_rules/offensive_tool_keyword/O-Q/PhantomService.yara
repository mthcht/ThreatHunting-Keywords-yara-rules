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
        $string1 = /.{0,1000}\/master\/PhantomService\/.{0,1000}/ nocase ascii wide
        // Description: Searches for and removes non-ASCII services that can't be easily removed by built-in Windows tools
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/PhantomService
        $string2 = /.{0,1000}\]\sFound\snon\-ASCII\sservice:\s.{0,1000}/ nocase ascii wide
        // Description: Searches for and removes non-ASCII services that can't be easily removed by built-in Windows tools
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/PhantomService
        $string3 = /.{0,1000}PhantomService\.csproj.{0,1000}/ nocase ascii wide
        // Description: Searches for and removes non-ASCII services that can't be easily removed by built-in Windows tools
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/PhantomService
        $string4 = /.{0,1000}PhantomService\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
