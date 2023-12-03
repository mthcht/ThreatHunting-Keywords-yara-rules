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
        $string1 = /.{0,1000}Get\-NetForestCatalog.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string2 = /.{0,1000}Get\-NetForestDomain.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string3 = /.{0,1000}Get\-NetForestTrust.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string4 = /.{0,1000}Get\-NetSession.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string5 = /.{0,1000}Get\-NetShare.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string6 = /.{0,1000}Get\-NetSubnet.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string7 = /.{0,1000}Get\-RegistryAutoLogon.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string8 = /.{0,1000}Get\-SiteListPassword.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string9 = /.{0,1000}Get\-TimedScreenshot.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string10 = /.{0,1000}Get\-UnquotedService.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
