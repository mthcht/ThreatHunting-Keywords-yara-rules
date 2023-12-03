rule Group3r
{
    meta:
        description = "Detection patterns for the tool 'Group3r' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Group3r"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string1 = /.{0,1000}\/LibSnaffle.{0,1000}/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string2 = /.{0,1000}\\LibSnaffle.{0,1000}/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string3 = /.{0,1000}EnumerateDomainGpo.{0,1000}/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string4 = /.{0,1000}Group3r\.cs.{0,1000}/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string5 = /.{0,1000}Group3r\.exe.{0,1000}/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string6 = /.{0,1000}Group3r\/Group3r.{0,1000}/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string7 = /.{0,1000}LibSnaffle\.ActiveDirectory.{0,1000}/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string8 = /.{0,1000}LibSnaffle\.FileDiscovery.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
