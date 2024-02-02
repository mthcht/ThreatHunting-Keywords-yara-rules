rule RandomPS_Scripts
{
    meta:
        description = "Detection patterns for the tool 'RandomPS-Scripts' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RandomPS-Scripts"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerShell wrapper for a Cylance Bypass
        // Reference: https://github.com/xorrior/RandomPS-Scripts
        $string1 = /\?function\sInvoke\-CylanceDisarm/ nocase ascii wide
        // Description: PowerShell wrapper for a Cylance Bypass
        // Reference: https://github.com/xorrior/RandomPS-Scripts
        $string2 = /DisableCylance\.ps1/ nocase ascii wide
        // Description: PowerShell wrapper for a Cylance Bypass
        // Reference: https://github.com/xorrior/RandomPS-Scripts
        $string3 = /Invoke\-CylanceDisarm\s\-ProcessID\s.{0,1000}\s\-DisableMemDef/ nocase ascii wide
        // Description: PowerShell Scripts focused on Post-Exploitation Capabilities
        // Reference: https://github.com/xorrior/RandomPS-Scripts
        $string4 = /Invoke\-WindowsEnum/ nocase ascii wide
        // Description: PowerShell Scripts focused on Post-Exploitation Capabilities
        // Reference: https://github.com/xorrior/RandomPS-Scripts
        $string5 = /Invoke\-WmicDriveBy\./ nocase ascii wide
        // Description: create or remove a backdoor using WMI event subscriptions
        // Reference: https://github.com/xorrior/RandomPS-Scripts
        $string6 = /Set\-WMIBackdoor\s\-URL\s/ nocase ascii wide
        // Description: create or remove a backdoor using WMI event subscriptions
        // Reference: https://github.com/xorrior/RandomPS-Scripts
        $string7 = /WMIBackdoor\.ps1/ nocase ascii wide

    condition:
        any of them
}
