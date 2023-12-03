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
        $string1 = /.{0,1000}\/Powermad\.git.{0,1000}/ nocase ascii wide
        // Description: PowerShell MachineAccountQuota and DNS exploit tools
        // Reference: https://github.com/Kevin-Robertson/Powermad
        $string2 = /.{0,1000}\\Powermad.{0,1000}/ nocase ascii wide
        // Description: PowerShell MachineAccountQuota and DNS exploit tools
        // Reference: https://github.com/Kevin-Robertson/Powermad
        $string3 = /.{0,1000}Invoke\-DNSUpdate\.ps1.{0,1000}/ nocase ascii wide
        // Description: PowerShell MachineAccountQuota and DNS exploit tools
        // Reference: https://github.com/Kevin-Robertson/Powermad
        $string4 = /.{0,1000}powermad\.ps1.{0,1000}/ nocase ascii wide
        // Description: PowerShell MachineAccountQuota and DNS exploit tools
        // Reference: https://github.com/Kevin-Robertson/Powermad
        $string5 = /.{0,1000}Powermad\.psd1.{0,1000}/ nocase ascii wide
        // Description: PowerShell MachineAccountQuota and DNS exploit tools
        // Reference: https://github.com/Kevin-Robertson/Powermad
        $string6 = /.{0,1000}Powermad\.psm1.{0,1000}/ nocase ascii wide
        // Description: PowerShell MachineAccountQuota and DNS exploit tools
        // Reference: https://github.com/Kevin-Robertson/Powermad
        $string7 = /.{0,1000}Powermad\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
