rule WMImplant
{
    meta:
        description = "Detection patterns for the tool 'WMImplant' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WMImplant"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines. but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.
        // Reference: https://github.com/FortyNorthSecurity/WMImplant
        $string1 = /WMImplant/ nocase ascii wide

    condition:
        any of them
}
