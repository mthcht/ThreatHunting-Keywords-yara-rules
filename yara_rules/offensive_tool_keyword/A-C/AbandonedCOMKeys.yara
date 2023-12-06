rule AbandonedCOMKeys
{
    meta:
        description = "Detection patterns for the tool 'AbandonedCOMKeys' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AbandonedCOMKeys"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Enumerates abandoned COM keys (specifically InprocServer32). Useful for persistence
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/AbandonedCOMKeys
        $string1 = /\/AbandonedCOMKeys\// nocase ascii wide
        // Description: Enumerates abandoned COM keys (specifically InprocServer32). Useful for persistence
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/AbandonedCOMKeys
        $string2 = /\\AbandonedCOMKeys\./ nocase ascii wide

    condition:
        any of them
}
