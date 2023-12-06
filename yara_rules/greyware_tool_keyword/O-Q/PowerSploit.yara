rule PowerSploit
{
    meta:
        description = "Detection patterns for the tool 'PowerSploit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerSploit"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string1 = /Get\-NetForestCatalog/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string2 = /Get\-NetForestDomain/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string3 = /Get\-NetForestTrust/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string4 = /Get\-NetSession/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string5 = /Get\-NetShare/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string6 = /Get\-NetSubnet/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string7 = /Get\-RegistryAutoLogon/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string8 = /Get\-SiteListPassword/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string9 = /Get\-TimedScreenshot/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string10 = /Get\-UnquotedService/ nocase ascii wide

    condition:
        any of them
}
