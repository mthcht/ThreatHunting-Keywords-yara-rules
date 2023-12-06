rule InvisibilityCloak
{
    meta:
        description = "Detection patterns for the tool 'InvisibilityCloak' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "InvisibilityCloak"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Proof-of-concept obfuscation toolkit for C# post-exploitation tools
        // Reference: https://github.com/h4wkst3r/InvisibilityCloak
        $string1 = /\s\-d\s.{0,1000}\s\-n\s.{0,1000}\s\-m\sreverse.{0,1000}\=/ nocase ascii wide
        // Description: Proof-of-concept obfuscation toolkit for C# post-exploitation tools
        // Reference: https://github.com/h4wkst3r/InvisibilityCloak
        $string2 = /\s\-d\s.{0,1000}\s\-n\s.{0,1000}\s\-m\srot13/ nocase ascii wide
        // Description: Proof-of-concept obfuscation toolkit for C# post-exploitation tools
        // Reference: https://github.com/h4wkst3r/InvisibilityCloak
        $string3 = /\s\-n\s.{0,1000}TotallyLegitTool/ nocase ascii wide
        // Description: Proof-of-concept obfuscation toolkit for C# post-exploitation tools
        // Reference: https://github.com/h4wkst3r/InvisibilityCloak
        $string4 = /InvisibilityCloak\.py/ nocase ascii wide

    condition:
        any of them
}
