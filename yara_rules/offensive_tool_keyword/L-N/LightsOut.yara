rule LightsOut
{
    meta:
        description = "Detection patterns for the tool 'LightsOut' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LightsOut"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Generate an obfuscated DLL that will disable AMSI & ETW
        // Reference: https://github.com/icyguider/LightsOut
        $string1 = /\/LightsOut\.git/ nocase ascii wide
        // Description: Generate an obfuscated DLL that will disable AMSI & ETW
        // Reference: https://github.com/icyguider/LightsOut
        $string2 = /icyguider\/LightsOut/ nocase ascii wide
        // Description: Generate an obfuscated DLL that will disable AMSI & ETW
        // Reference: https://github.com/icyguider/LightsOut
        $string3 = /lightsout\.py/ nocase ascii wide
        // Description: Generate an obfuscated DLL that will disable AMSI & ETW
        // Reference: https://github.com/icyguider/LightsOut
        $string4 = /LightsOut\-master\.zip/ nocase ascii wide

    condition:
        any of them
}
