rule SpookFlare
{
    meta:
        description = "Detection patterns for the tool 'SpookFlare' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpookFlare"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SpookFlare has a different perspective to bypass security measures and it gives you the opportunity to bypass the endpoint countermeasures at the client-side detection and network-side detection. SpookFlare is a loader/dropper generator for Meterpreter. Empire. Koadic etc. SpookFlare has obfuscation. encoding. run-time code compilation and character substitution features.
        // Reference: https://github.com/hlldz/SpookFlare
        $string1 = /SpookFlare/ nocase ascii wide

    condition:
        any of them
}
