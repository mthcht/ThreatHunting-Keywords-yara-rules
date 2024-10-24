rule Group3r
{
    meta:
        description = "Detection patterns for the tool 'Group3r' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Group3r"
        rule_category = "signature_keyword"

    strings:
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string1 = /HackTool\.MSIL\.Gropire\.REDT/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string2 = /HackTool\:MSIL\/Snaffler/ nocase ascii wide
        // Description: Find vulnerabilities in AD Group Policy
        // Reference: https://github.com/Group3r/Group3r
        $string3 = /MSIL\/Riskware\.Snaffler/ nocase ascii wide

    condition:
        any of them
}
