rule LAPSToolkit
{
    meta:
        description = "Detection patterns for the tool 'LAPSToolkit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LAPSToolkit"
        rule_category = "signature_keyword"

    strings:
        // Description: Functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsofts Local Administrator Password Solution (LAPS). It includes finding groups specifically delegated by sysadmins. finding users with All Extended Rights that can view passwords. and viewing all computers with LAPS enabled
        // Reference: https://github.com/leoloobeek/LAPSToolkit
        $string1 = /HackTool\.PS1\.PowerSploit/ nocase ascii wide
        // Description: Functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsofts Local Administrator Password Solution (LAPS). It includes finding groups specifically delegated by sysadmins. finding users with All Extended Rights that can view passwords. and viewing all computers with LAPS enabled
        // Reference: https://github.com/leoloobeek/LAPSToolkit
        $string2 = /HTool\-EmpireAgent/ nocase ascii wide

    condition:
        any of them
}
