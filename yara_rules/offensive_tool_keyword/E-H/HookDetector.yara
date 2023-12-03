rule HookDetector
{
    meta:
        description = "Detection patterns for the tool 'HookDetector' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HookDetector"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Detects hooked Native API functions in the current process indicating the presence of EDR	
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector
        $string1 = /.{0,1000}\s.{0,1000}\s0x.{0,1000}\s\-\sHOOK\sDETECTED.{0,1000}/ nocase ascii wide
        // Description: Detects hooked Native API functions in the current process indicating the presence of EDR	
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector
        $string2 = /.{0,1000}\/HookDetector\.exe.{0,1000}/ nocase ascii wide
        // Description: Detects hooked Native API functions in the current process indicating the presence of EDR	
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector
        $string3 = /.{0,1000}\\HookDetector\.csproj.{0,1000}/ nocase ascii wide
        // Description: Detects hooked Native API functions in the current process indicating the presence of EDR	
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector
        $string4 = /.{0,1000}\\HookDetector\.exe.{0,1000}/ nocase ascii wide
        // Description: Detects hooked Native API functions in the current process indicating the presence of EDR	
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector
        $string5 = /.{0,1000}master\/HookDetector.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
