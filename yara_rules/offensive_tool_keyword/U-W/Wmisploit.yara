rule Wmisploit
{
    meta:
        description = "Detection patterns for the tool 'Wmisploit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Wmisploit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: WmiSploit is a small set of PowerShell scripts that leverage the WMI service for post-exploitation use.
        // Reference: https://github.com/secabstraction/WmiSploit
        $string1 = /.{0,1000}\s\-RemotePath\s.{0,1000}\\Windows\\System32\\SAM\s\-LocalPath\s.{0,1000}\\tmp\\.{0,1000}/ nocase ascii wide
        // Description: WmiSploit is a small set of PowerShell scripts that leverage the WMI service for post-exploitation use.
        // Reference: https://github.com/secabstraction/WmiSploit
        $string2 = /.{0,1000}\/wmisploit.{0,1000}/ nocase ascii wide
        // Description: WmiSploit is a small set of PowerShell scripts that leverage the WMI service for post-exploitation use.
        // Reference: https://github.com/secabstraction/WmiSploit
        $string3 = /.{0,1000}Enter\-WmiShell\s.{0,1000}/ nocase ascii wide
        // Description: WmiSploit is a small set of PowerShell scripts that leverage the WMI service for post-exploitation use.
        // Reference: https://github.com/secabstraction/WmiSploit
        $string4 = /.{0,1000}Enter\-WmiShell\.ps1.{0,1000}/ nocase ascii wide
        // Description: WmiSploit is a small set of PowerShell scripts that leverage the WMI service for post-exploitation use.
        // Reference: https://github.com/secabstraction/WmiSploit
        $string5 = /.{0,1000}Invoke\-WmiCommand.{0,1000}/ nocase ascii wide
        // Description: WmiSploit is a small set of PowerShell scripts that leverage the WMI service for post-exploitation use.
        // Reference: https://github.com/secabstraction/WmiSploit
        $string6 = /.{0,1000}Invoke\-WmiShadowCopy.{0,1000}/ nocase ascii wide
        // Description: WmiSploit is a small set of PowerShell scripts that leverage the WMI service for post-exploitation use.
        // Reference: https://github.com/secabstraction/WmiSploit
        $string7 = /.{0,1000}New\-WmiSession\.ps1.{0,1000}/ nocase ascii wide
        // Description: WmiSploit is a small set of PowerShell scripts that leverage the WMI service for post-exploitation use.
        // Reference: https://github.com/secabstraction/WmiSploit
        $string8 = /.{0,1000}WmiSploit\.git.{0,1000}/ nocase ascii wide
        // Description: WmiSploit is a small set of PowerShell scripts that leverage the WMI service for post-exploitation use.
        // Reference: https://github.com/secabstraction/WmiSploit
        $string9 = /.{0,1000}WmiSploit\-master\/zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
