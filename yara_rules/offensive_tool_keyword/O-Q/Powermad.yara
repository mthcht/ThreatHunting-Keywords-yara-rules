rule Powermad
{
    meta:
        description = "Detection patterns for the tool 'Powermad' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Powermad"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerShell MachineAccountQuota and DNS exploit tools
        // Reference: https://github.com/Kevin-Robertson/Powermad
        $string1 = /\/Powermad\.git/ nocase ascii wide
        // Description: PowerShell MachineAccountQuota and DNS exploit tools
        // Reference: https://github.com/Kevin-Robertson/Powermad
        $string2 = /\\Powermad/ nocase ascii wide
        // Description: PowerShell MachineAccountQuota and DNS exploit tools
        // Reference: https://github.com/Kevin-Robertson/Powermad
        $string3 = /Invoke\-DNSUpdate\.ps1/ nocase ascii wide
        // Description: PowerShell MachineAccountQuota and DNS exploit tools
        // Reference: https://github.com/Kevin-Robertson/Powermad
        $string4 = /powermad\.ps1/ nocase ascii wide
        // Description: PowerShell MachineAccountQuota and DNS exploit tools
        // Reference: https://github.com/Kevin-Robertson/Powermad
        $string5 = /Powermad\.psd1/ nocase ascii wide
        // Description: PowerShell MachineAccountQuota and DNS exploit tools
        // Reference: https://github.com/Kevin-Robertson/Powermad
        $string6 = /Powermad\.psm1/ nocase ascii wide
        // Description: PowerShell MachineAccountQuota and DNS exploit tools
        // Reference: https://github.com/Kevin-Robertson/Powermad
        $string7 = /Powermad\-master/ nocase ascii wide

    condition:
        any of them
}
