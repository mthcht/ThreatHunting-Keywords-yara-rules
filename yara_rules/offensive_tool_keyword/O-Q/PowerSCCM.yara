rule PowerSCCM
{
    meta:
        description = "Detection patterns for the tool 'PowerSCCM' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerSCCM"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerSCCM - PowerShell module to interact with SCCM deployments
        // Reference: https://github.com/PowerShellMafia/PowerSCCM
        $string1 = /\/PowerSCCM\.git/ nocase ascii wide
        // Description: PowerSCCM - PowerShell module to interact with SCCM deployments
        // Reference: https://github.com/PowerShellMafia/PowerSCCM
        $string2 = /0ac82760\-3e0d\-4124\-bd1c\-92c8dab97171/ nocase ascii wide
        // Description: PowerSCCM - PowerShell module to interact with SCCM deployments
        // Reference: https://github.com/PowerShellMafia/PowerSCCM
        $string3 = /PowerSCCM\.ps1/ nocase ascii wide
        // Description: PowerSCCM - PowerShell module to interact with SCCM deployments
        // Reference: https://github.com/PowerShellMafia/PowerSCCM
        $string4 = /PowerSCCM\.psd1/ nocase ascii wide
        // Description: PowerSCCM - PowerShell module to interact with SCCM deployments
        // Reference: https://github.com/PowerShellMafia/PowerSCCM
        $string5 = /PowerSCCM\.psm1/ nocase ascii wide
        // Description: PowerSCCM - PowerShell module to interact with SCCM deployments
        // Reference: https://github.com/PowerShellMafia/PowerSCCM
        $string6 = /PowerSCCM\-master/ nocase ascii wide
        // Description: PowerSCCM - PowerShell module to interact with SCCM deployments
        // Reference: https://github.com/PowerShellMafia/PowerSCCM
        $string7 = /PowerShellMafia\/PowerSCCM/ nocase ascii wide

    condition:
        any of them
}
