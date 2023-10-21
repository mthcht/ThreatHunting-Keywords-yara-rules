rule COMHunter
{
    meta:
        description = "Detection patterns for the tool 'COMHunter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "COMHunter"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Enumerates COM servers set in LocalServer32 and InProc32 keys on a system using WMI
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/COMHunter
        $string1 = /COMHunter.*\s\-inproc/ nocase ascii wide
        // Description: Enumerates COM servers set in LocalServer32 and InProc32 keys on a system using WMI
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/COMHunter
        $string2 = /COMHunter.*\s\-localserver/ nocase ascii wide
        // Description: Enumerates COM servers set in LocalServer32 and InProc32 keys on a system using WMI
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/COMHunter
        $string3 = /COMHunter\.csproj/ nocase ascii wide
        // Description: Enumerates COM servers set in LocalServer32 and InProc32 keys on a system using WMI
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/COMHunter
        $string4 = /COMHunter\.exe/ nocase ascii wide
        // Description: Enumerates COM servers set in LocalServer32 and InProc32 keys on a system using WMI
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/COMHunter
        $string5 = /COMHunter\.sln/ nocase ascii wide
        // Description: Enumerates COM servers set in LocalServer32 and InProc32 keys on a system using WMI
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/COMHunter
        $string6 = /github.*\/COMHunter\// nocase ascii wide

    condition:
        any of them
}