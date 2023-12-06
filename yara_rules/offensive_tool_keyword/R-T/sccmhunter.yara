rule sccmhunter
{
    meta:
        description = "Detection patterns for the tool 'sccmhunter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sccmhunter"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SCCMHunter is a post-ex tool built to streamline identifying profiling and attacking SCCM related assets in an Active Directory domain
        // Reference: https://github.com/garrettfoster13/sccmhunter
        $string1 = /\.sccmhunter/ nocase ascii wide
        // Description: SCCMHunter is a post-ex tool built to streamline identifying profiling and attacking SCCM related assets in an Active Directory domain
        // Reference: https://github.com/garrettfoster13/sccmhunter
        $string2 = /\/sccmhunter/ nocase ascii wide
        // Description: SCCMHunter is a post-ex tool built to streamline identifying profiling and attacking SCCM related assets in an Active Directory domain
        // Reference: https://github.com/garrettfoster13/sccmhunter
        $string3 = /cmpivot\.py/ nocase ascii wide
        // Description: SCCMHunter is a post-ex tool built to streamline identifying profiling and attacking SCCM related assets in an Active Directory domain
        // Reference: https://github.com/garrettfoster13/sccmhunter
        $string4 = /sccmhunter\.db/ nocase ascii wide
        // Description: SCCMHunter is a post-ex tool built to streamline identifying profiling and attacking SCCM related assets in an Active Directory domain
        // Reference: https://github.com/garrettfoster13/sccmhunter
        $string5 = /sccmhunter\.git/ nocase ascii wide
        // Description: SCCMHunter is a post-ex tool built to streamline identifying profiling and attacking SCCM related assets in an Active Directory domain
        // Reference: https://github.com/garrettfoster13/sccmhunter
        $string6 = /sccmhunter\.py/ nocase ascii wide
        // Description: SCCMHunter is a post-ex tool built to streamline identifying profiling and attacking SCCM related assets in an Active Directory domain
        // Reference: https://github.com/garrettfoster13/sccmhunter
        $string7 = /sccmwtf\.py/ nocase ascii wide

    condition:
        any of them
}
