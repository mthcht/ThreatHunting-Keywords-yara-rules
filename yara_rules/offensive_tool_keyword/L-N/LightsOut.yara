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
        $string1 = /.{0,1000}\/LightsOut\.git.{0,1000}/ nocase ascii wide
        // Description: Generate an obfuscated DLL that will disable AMSI & ETW
        // Reference: https://github.com/icyguider/LightsOut
        $string2 = /.{0,1000}icyguider\/LightsOut.{0,1000}/ nocase ascii wide
        // Description: Generate an obfuscated DLL that will disable AMSI & ETW
        // Reference: https://github.com/icyguider/LightsOut
        $string3 = /.{0,1000}lightsout\.py.{0,1000}/ nocase ascii wide
        // Description: Generate an obfuscated DLL that will disable AMSI & ETW
        // Reference: https://github.com/icyguider/LightsOut
        $string4 = /.{0,1000}LightsOut\-master\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
