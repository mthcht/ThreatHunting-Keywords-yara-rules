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
        $string1 = /\s.{0,1000}\s0x.{0,1000}\s\-\sHOOK\sDETECTED/ nocase ascii wide
        // Description: Detects hooked Native API functions in the current process indicating the presence of EDR
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector
        $string2 = /\/HookDetector\.exe/ nocase ascii wide
        // Description: Detects hooked Native API functions in the current process indicating the presence of EDR
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector
        $string3 = /\\HookDetector\.csproj/ nocase ascii wide
        // Description: Detects hooked Native API functions in the current process indicating the presence of EDR
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector
        $string4 = /\\HookDetector\.exe/ nocase ascii wide
        // Description: Detects hooked Native API functions in the current process indicating the presence of EDR
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector
        $string5 = /master\/HookDetector/ nocase ascii wide

    condition:
        any of them
}
