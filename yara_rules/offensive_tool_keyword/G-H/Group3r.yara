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
        $string1 = /\/LibSnaffle/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string2 = /\\LibSnaffle/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string3 = /EnumerateDomainGpo/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string4 = /Group3r\.cs/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string5 = /Group3r\.exe/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string6 = /Group3r\/Group3r/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string7 = /LibSnaffle\.ActiveDirectory/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string8 = /LibSnaffle\.FileDiscovery/ nocase ascii wide

    condition:
        any of them
}
