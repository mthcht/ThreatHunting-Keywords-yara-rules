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
        $string1 = /.{0,1000}\/PowerSCCM\.git.{0,1000}/ nocase ascii wide
        // Description: PowerSCCM - PowerShell module to interact with SCCM deployments
        // Reference: https://github.com/PowerShellMafia/PowerSCCM
        $string2 = /.{0,1000}0ac82760\-3e0d\-4124\-bd1c\-92c8dab97171.{0,1000}/ nocase ascii wide
        // Description: PowerSCCM - PowerShell module to interact with SCCM deployments
        // Reference: https://github.com/PowerShellMafia/PowerSCCM
        $string3 = /.{0,1000}PowerSCCM\.ps1.{0,1000}/ nocase ascii wide
        // Description: PowerSCCM - PowerShell module to interact with SCCM deployments
        // Reference: https://github.com/PowerShellMafia/PowerSCCM
        $string4 = /.{0,1000}PowerSCCM\.psd1.{0,1000}/ nocase ascii wide
        // Description: PowerSCCM - PowerShell module to interact with SCCM deployments
        // Reference: https://github.com/PowerShellMafia/PowerSCCM
        $string5 = /.{0,1000}PowerSCCM\.psm1.{0,1000}/ nocase ascii wide
        // Description: PowerSCCM - PowerShell module to interact with SCCM deployments
        // Reference: https://github.com/PowerShellMafia/PowerSCCM
        $string6 = /.{0,1000}PowerSCCM\-master.{0,1000}/ nocase ascii wide
        // Description: PowerSCCM - PowerShell module to interact with SCCM deployments
        // Reference: https://github.com/PowerShellMafia/PowerSCCM
        $string7 = /.{0,1000}PowerShellMafia\/PowerSCCM.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
