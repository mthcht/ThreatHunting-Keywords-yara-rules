rule rdpscraper
{
    meta:
        description = "Detection patterns for the tool 'rdpscraper' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rdpscraper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: rdpscraper - Enumerates users based off RDP Screenshots
        // Reference: https://github.com/x90skysn3k/rdpscraper
        $string1 = /rdpscraper/ nocase ascii wide

    condition:
        any of them
}
