rule translate_goog
{
    meta:
        description = "Detection patterns for the tool 'translate.goog' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "translate.goog"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: accessing github through google translate (evasion) false positive risk
        // Reference: https://*-com.translate.goog/*
        $string1 = /https\:\/\/github\-com\.translate\.goog\// nocase ascii wide

    condition:
        any of them
}
