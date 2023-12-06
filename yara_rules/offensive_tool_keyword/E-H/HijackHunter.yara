rule HijackHunter
{
    meta:
        description = "Detection patterns for the tool 'HijackHunter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HijackHunter"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Parses a target's PE header in order to find lined DLLs vulnerable to hijacking. Provides reasoning and abuse techniques for each detected hijack opportunity
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/HijackHunter
        $string1 = /\/HijackHunter\// nocase ascii wide
        // Description: Parses a target's PE header in order to find lined DLLs vulnerable to hijacking. Provides reasoning and abuse techniques for each detected hijack opportunity
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/HijackHunter
        $string2 = /\\HijackHunter\\/ nocase ascii wide
        // Description: Parses a target's PE header in order to find lined DLLs vulnerable to hijacking. Provides reasoning and abuse techniques for each detected hijack opportunity
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/HijackHunter
        $string3 = /dll.{0,1000}\s\[HIJACKABLE\]/ nocase ascii wide
        // Description: Parses a target's PE header in order to find lined DLLs vulnerable to hijacking. Provides reasoning and abuse techniques for each detected hijack opportunity
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/HijackHunter
        $string4 = /HijackHunter\.csproj/ nocase ascii wide
        // Description: Parses a target's PE header in order to find lined DLLs vulnerable to hijacking. Provides reasoning and abuse techniques for each detected hijack opportunity
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/HijackHunter
        $string5 = /HijackHunter\.exe/ nocase ascii wide
        // Description: Parses a target's PE header in order to find lined DLLs vulnerable to hijacking. Provides reasoning and abuse techniques for each detected hijack opportunity
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/HijackHunter
        $string6 = /hijackProgDirMissingDll/ nocase ascii wide

    condition:
        any of them
}
