rule adiskreader
{
    meta:
        description = "Detection patterns for the tool 'adiskreader' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adiskreader"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Async Python library to parse local and remote disk images
        // Reference: https://github.com/skelsec/adiskreader
        $string1 = /\#\sadiskreader\s/ nocase ascii wide
        // Description: Async Python library to parse local and remote disk images
        // Reference: https://github.com/skelsec/adiskreader
        $string2 = /\\adiskreader\\/ nocase ascii wide
        // Description: Async Python library to parse local and remote disk images
        // Reference: https://github.com/skelsec/adiskreader
        $string3 = /adiskreader\.disks\.raw/ nocase ascii wide
        // Description: Async Python library to parse local and remote disk images
        // Reference: https://github.com/skelsec/adiskreader
        $string4 = /adiskreader\.disks\.vhdx/ nocase ascii wide

    condition:
        any of them
}
