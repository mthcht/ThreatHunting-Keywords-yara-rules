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
        $string1 = /.{0,1000}COMHunter.{0,1000}\s\-inproc.{0,1000}/ nocase ascii wide
        // Description: Enumerates COM servers set in LocalServer32 and InProc32 keys on a system using WMI
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/COMHunter
        $string2 = /.{0,1000}COMHunter.{0,1000}\s\-localserver.{0,1000}/ nocase ascii wide
        // Description: Enumerates COM servers set in LocalServer32 and InProc32 keys on a system using WMI
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/COMHunter
        $string3 = /.{0,1000}COMHunter\.csproj.{0,1000}/ nocase ascii wide
        // Description: Enumerates COM servers set in LocalServer32 and InProc32 keys on a system using WMI
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/COMHunter
        $string4 = /.{0,1000}COMHunter\.exe.{0,1000}/ nocase ascii wide
        // Description: Enumerates COM servers set in LocalServer32 and InProc32 keys on a system using WMI
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/COMHunter
        $string5 = /.{0,1000}COMHunter\.sln.{0,1000}/ nocase ascii wide
        // Description: Enumerates COM servers set in LocalServer32 and InProc32 keys on a system using WMI
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/COMHunter
        $string6 = /.{0,1000}github.{0,1000}\/COMHunter\/.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
