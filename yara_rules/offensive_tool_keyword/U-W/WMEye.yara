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
        $string1 = /\/wmeye\// nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for lateral movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string2 = /pwn1sher\/WMEye/ nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for lateral movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string3 = /wmeye\.csproj/ nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for lateral movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string4 = /wmeye\.exe\s/ nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for lateral movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string5 = /wmeye\.sln/ nocase ascii wide

    condition:
        any of them
}
