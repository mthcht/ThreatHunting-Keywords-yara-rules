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
        $string1 = /.{0,1000}\.sccmhunter.{0,1000}/ nocase ascii wide
        // Description: SCCMHunter is a post-ex tool built to streamline identifying profiling and attacking SCCM related assets in an Active Directory domain
        // Reference: https://github.com/garrettfoster13/sccmhunter
        $string2 = /.{0,1000}\/sccmhunter.{0,1000}/ nocase ascii wide
        // Description: SCCMHunter is a post-ex tool built to streamline identifying profiling and attacking SCCM related assets in an Active Directory domain
        // Reference: https://github.com/garrettfoster13/sccmhunter
        $string3 = /.{0,1000}cmpivot\.py.{0,1000}/ nocase ascii wide
        // Description: SCCMHunter is a post-ex tool built to streamline identifying profiling and attacking SCCM related assets in an Active Directory domain
        // Reference: https://github.com/garrettfoster13/sccmhunter
        $string4 = /.{0,1000}sccmhunter\.db/ nocase ascii wide
        // Description: SCCMHunter is a post-ex tool built to streamline identifying profiling and attacking SCCM related assets in an Active Directory domain
        // Reference: https://github.com/garrettfoster13/sccmhunter
        $string5 = /.{0,1000}sccmhunter\.git.{0,1000}/ nocase ascii wide
        // Description: SCCMHunter is a post-ex tool built to streamline identifying profiling and attacking SCCM related assets in an Active Directory domain
        // Reference: https://github.com/garrettfoster13/sccmhunter
        $string6 = /.{0,1000}sccmhunter\.py.{0,1000}/ nocase ascii wide
        // Description: SCCMHunter is a post-ex tool built to streamline identifying profiling and attacking SCCM related assets in an Active Directory domain
        // Reference: https://github.com/garrettfoster13/sccmhunter
        $string7 = /.{0,1000}sccmwtf\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
