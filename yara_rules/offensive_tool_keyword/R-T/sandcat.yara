rule sandcat
{
    meta:
        description = "Detection patterns for the tool 'sandcat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sandcat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An open-source pentest oriented web browser
        // Reference: https://github.com/syhunt/sandcat
        $string1 = /\/sandcat\.git/ nocase ascii wide
        // Description: An open-source pentest oriented web browser
        // Reference: https://github.com/syhunt/sandcat
        $string2 = /syhunt\.com\/sandcat\// nocase ascii wide
        // Description: An open-source pentest oriented web browser
        // Reference: https://github.com/syhunt/sandcat
        $string3 = /syhunt\/sandcat/ nocase ascii wide
        // Description: An open-source pentest oriented web browser
        // Reference: https://github.com/syhunt/sandcat
        $string4 = /syhunt\-sandcat\-.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}
