rule PassSpray
{
    meta:
        description = "Detection patterns for the tool 'PassSpray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PassSpray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Domain Password Spray
        // Reference: https://github.com/Leo4j/PassSpray
        $string1 = /\sPassSpray\.ps1/ nocase ascii wide
        // Description: Domain Password Spray
        // Reference: https://github.com/Leo4j/PassSpray
        $string2 = /\/PassSpray\.git/ nocase ascii wide
        // Description: Domain Password Spray
        // Reference: https://github.com/Leo4j/PassSpray
        $string3 = /\/PassSpray\.ps1/ nocase ascii wide
        // Description: Domain Password Spray
        // Reference: https://github.com/Leo4j/PassSpray
        $string4 = /\\PassSpray\.ps1/ nocase ascii wide
        // Description: Domain Password Spray
        // Reference: https://github.com/Leo4j/PassSpray
        $string5 = /24d7bda466850d93fc1883a3937e1317fbb3f9e631ab0d2a4fa0b45c2c21c24f/ nocase ascii wide
        // Description: Domain Password Spray
        // Reference: https://github.com/Leo4j/PassSpray
        $string6 = /Invoke\-PassSpray/ nocase ascii wide
        // Description: Domain Password Spray
        // Reference: https://github.com/Leo4j/PassSpray
        $string7 = /Leo4j\/PassSpray/ nocase ascii wide

    condition:
        any of them
}
