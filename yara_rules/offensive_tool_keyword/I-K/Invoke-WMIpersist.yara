rule Invoke_WMIpersist
{
    meta:
        description = "Detection patterns for the tool 'Invoke-WMIpersist' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-WMIpersist"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A powershell script to create WMI Event subscription persistence
        // Reference: https://github.com/bspence7337/Invoke-WMIpersist
        $string1 = /8d3945448815d156c064445585aa7cf51a5c30e9f96d7598e8ca323815f9aee3/ nocase ascii wide
        // Description: A powershell script to create WMI Event subscription persistence
        // Reference: https://github.com/bspence7337/Invoke-WMIpersist
        $string2 = /Invoke\-WMIpersist/ nocase ascii wide
        // Description: A powershell script to create WMI Event subscription persistence
        // Reference: https://github.com/bspence7337/Invoke-WMIpersist
        $string3 = /Invoke\-WMIpersist\.ps1/ nocase ascii wide

    condition:
        any of them
}
