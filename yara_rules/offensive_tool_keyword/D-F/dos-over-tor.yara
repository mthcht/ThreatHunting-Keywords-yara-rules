rule dos_over_tor
{
    meta:
        description = "Detection patterns for the tool 'dos-over-tor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dos-over-tor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Proof of concept denial of service over TOR stress test tool. Is multi-threaded and supports multiple attack vectors.
        // Reference: https://github.com/skizap/dos-over-tor
        $string1 = /dos\-over\-tor/ nocase ascii wide

    condition:
        any of them
}
