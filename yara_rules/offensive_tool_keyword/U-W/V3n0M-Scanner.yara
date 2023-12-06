rule V3n0M_Scanner
{
    meta:
        description = "Detection patterns for the tool 'V3n0M-Scanner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "V3n0M-Scanner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: V3n0M is a free and open source scanner. Evolved from baltazars scanner. it has adapted several new features that improve fuctionality and usability. It is mostly experimental software. This program is for finding and executing various vulnerabilities. It scavenges the web using dorks and organizes the URLs it finds. Use at your own risk.
        // Reference: https://github.com/v3n0m-Scanner/V3n0M-Scanner
        $string1 = /V3n0M\-Scanner/ nocase ascii wide

    condition:
        any of them
}
