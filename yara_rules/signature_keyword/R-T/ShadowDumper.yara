rule ShadowDumper
{
    meta:
        description = "Detection patterns for the tool 'ShadowDumper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShadowDumper"
        rule_category = "signature_keyword"

    strings:
        // Description: dump LSASS memory
        // Reference: https://github.com/Offensive-Panda/ShadowDumper
        $string1 = /Win64\.ShadowDumper/ nocase ascii wide

    condition:
        any of them
}
