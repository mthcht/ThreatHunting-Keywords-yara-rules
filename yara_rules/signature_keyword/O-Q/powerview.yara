rule powerview
{
    meta:
        description = "Detection patterns for the tool 'powerview' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powerview"
        rule_category = "signature_keyword"

    strings:
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string1 = /ATK\/PowSploit\-A/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string2 = /HackTool\.PowerShell\.PowerSploit/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string3 = /HackTool\.PowerShell\.PowerSploit/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string4 = /HackTool\.PowerView/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string5 = /HackTool\.PS1\.PowerSploit/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string6 = /HackTool\.PS1\.PowerSploit/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string7 = /HackTool\:PowerShell\/PowerView/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string8 = /HackTool\:PowerShell\/PowerView/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string9 = /HTool\-EmpireAgent/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string10 = /HTool\-EmpireAgent/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string11 = /Trojan\.HackTool\.PowerSploit/ nocase ascii wide
        // Description: PowerView is a PowerShell tool to gain network situational awareness on Windows domains
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
        $string12 = /Trojan\.HackTool\.PowerSploit/ nocase ascii wide

    condition:
        any of them
}
