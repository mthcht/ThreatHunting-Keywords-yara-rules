rule evilrdp
{
    meta:
        description = "Detection patterns for the tool 'evilrdp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "evilrdp"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string1 = /dorgreen1\@gmail\.com/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string2 = /info\@skelsecprojects\.com/ nocase ascii wide

    condition:
        any of them
}
