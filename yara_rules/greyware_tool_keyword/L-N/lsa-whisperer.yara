rule lsa_whisperer
{
    meta:
        description = "Detection patterns for the tool 'lsa-whisperer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lsa-whisperer"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Tools for interacting with authentication packages using their individual message protocols
        // Reference: https://github.com/EvanMcBroom/lsa-whisperer
        $string1 = /\/lsa\-whisperer\-.{0,1000}\.zip/ nocase ascii wide
        // Description: Tools for interacting with authentication packages using their individual message protocols
        // Reference: https://github.com/EvanMcBroom/lsa-whisperer
        $string2 = /\/lsa\-whisperer\.git/ nocase ascii wide
        // Description: Tools for interacting with authentication packages using their individual message protocols
        // Reference: https://github.com/EvanMcBroom/lsa-whisperer
        $string3 = /\\lsa\-whisperer\-/ nocase ascii wide
        // Description: Tools for interacting with authentication packages using their individual message protocols
        // Reference: https://github.com/EvanMcBroom/lsa-whisperer
        $string4 = /EvanMcBroom\/lsa\-whisperer/ nocase ascii wide

    condition:
        any of them
}
