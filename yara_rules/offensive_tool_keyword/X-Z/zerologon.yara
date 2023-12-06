rule zerologon
{
    meta:
        description = "Detection patterns for the tool 'zerologon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "zerologon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Zerologon CVE exploitation
        // Reference: https://github.com/michaelpoznecki/zerologon
        $string1 = /nrpc\.py/ nocase ascii wide

    condition:
        any of them
}
