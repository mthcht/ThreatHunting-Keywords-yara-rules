rule GTFOBLookup
{
    meta:
        description = "Detection patterns for the tool 'GTFOBLookup' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GTFOBLookup"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Offline command line lookup utility for GTFOBins and LOLBAS.
        // Reference: https://github.com/nccgroup/GTFOBLookup
        $string1 = /GTFOBLookup/ nocase ascii wide

    condition:
        any of them
}
