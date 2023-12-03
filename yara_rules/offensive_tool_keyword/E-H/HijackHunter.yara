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
        $string1 = /.{0,1000}\/HijackHunter\/.{0,1000}/ nocase ascii wide
        // Description: Parses a target's PE header in order to find lined DLLs vulnerable to hijacking. Provides reasoning and abuse techniques for each detected hijack opportunity
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/HijackHunter
        $string2 = /.{0,1000}\\HijackHunter\\.{0,1000}/ nocase ascii wide
        // Description: Parses a target's PE header in order to find lined DLLs vulnerable to hijacking. Provides reasoning and abuse techniques for each detected hijack opportunity
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/HijackHunter
        $string3 = /.{0,1000}dll.{0,1000}\s\[HIJACKABLE\].{0,1000}/ nocase ascii wide
        // Description: Parses a target's PE header in order to find lined DLLs vulnerable to hijacking. Provides reasoning and abuse techniques for each detected hijack opportunity
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/HijackHunter
        $string4 = /.{0,1000}HijackHunter\.csproj.{0,1000}/ nocase ascii wide
        // Description: Parses a target's PE header in order to find lined DLLs vulnerable to hijacking. Provides reasoning and abuse techniques for each detected hijack opportunity
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/HijackHunter
        $string5 = /.{0,1000}HijackHunter\.exe.{0,1000}/ nocase ascii wide
        // Description: Parses a target's PE header in order to find lined DLLs vulnerable to hijacking. Provides reasoning and abuse techniques for each detected hijack opportunity
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/HijackHunter
        $string6 = /.{0,1000}hijackProgDirMissingDll.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
