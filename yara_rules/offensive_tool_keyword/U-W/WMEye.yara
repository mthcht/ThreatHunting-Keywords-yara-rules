rule WMEye
{
    meta:
        description = "Detection patterns for the tool 'WMEye' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WMEye"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for lateral movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string1 = /.{0,1000}\/wmeye\/.{0,1000}/ nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for lateral movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string2 = /.{0,1000}pwn1sher\/WMEye.{0,1000}/ nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for lateral movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string3 = /.{0,1000}wmeye\.csproj.{0,1000}/ nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for lateral movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string4 = /.{0,1000}wmeye\.exe\s.{0,1000}/ nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for lateral movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string5 = /.{0,1000}wmeye\.sln.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
