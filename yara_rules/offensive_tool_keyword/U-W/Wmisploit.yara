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
        $string1 = /\s\-RemotePath\s.{0,1000}\\Windows\\System32\\SAM\s\-LocalPath\s.{0,1000}\\tmp\\/ nocase ascii wide
        // Description: WmiSploit is a small set of PowerShell scripts that leverage the WMI service for post-exploitation use.
        // Reference: https://github.com/secabstraction/WmiSploit
        $string2 = /\/wmisploit/ nocase ascii wide
        // Description: WmiSploit is a small set of PowerShell scripts that leverage the WMI service for post-exploitation use.
        // Reference: https://github.com/secabstraction/WmiSploit
        $string3 = /Enter\-WmiShell\s/ nocase ascii wide
        // Description: WmiSploit is a small set of PowerShell scripts that leverage the WMI service for post-exploitation use.
        // Reference: https://github.com/secabstraction/WmiSploit
        $string4 = /Enter\-WmiShell\.ps1/ nocase ascii wide
        // Description: WmiSploit is a small set of PowerShell scripts that leverage the WMI service for post-exploitation use.
        // Reference: https://github.com/secabstraction/WmiSploit
        $string5 = /Invoke\-WmiCommand/ nocase ascii wide
        // Description: WmiSploit is a small set of PowerShell scripts that leverage the WMI service for post-exploitation use.
        // Reference: https://github.com/secabstraction/WmiSploit
        $string6 = /Invoke\-WmiShadowCopy/ nocase ascii wide
        // Description: WmiSploit is a small set of PowerShell scripts that leverage the WMI service for post-exploitation use.
        // Reference: https://github.com/secabstraction/WmiSploit
        $string7 = /New\-WmiSession\.ps1/ nocase ascii wide
        // Description: WmiSploit is a small set of PowerShell scripts that leverage the WMI service for post-exploitation use.
        // Reference: https://github.com/secabstraction/WmiSploit
        $string8 = /WmiSploit\.git/ nocase ascii wide
        // Description: WmiSploit is a small set of PowerShell scripts that leverage the WMI service for post-exploitation use.
        // Reference: https://github.com/secabstraction/WmiSploit
        $string9 = /WmiSploit\-master\/zip/ nocase ascii wide

    condition:
        any of them
}
