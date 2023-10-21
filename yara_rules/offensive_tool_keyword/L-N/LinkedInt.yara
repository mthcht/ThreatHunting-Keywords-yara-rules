rule LinkedInt
{
    meta:
        description = "Detection patterns for the tool 'LinkedInt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LinkedInt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: LinkedInt: A LinkedIn scraper for reconnaissance during adversary simulation
        // Reference: https://github.com/mdsecactivebreach/LinkedInt
        $string1 = /LinkedInt/ nocase ascii wide

    condition:
        any of them
}