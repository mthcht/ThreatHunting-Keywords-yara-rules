rule Password_Scripts
{
    meta:
        description = "Detection patterns for the tool 'Password-Scripts' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Password-Scripts"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Password Scripts xploitation 
        // Reference: https://github.com/laconicwolf/Password-Scripts
        $string1 = /Password\-Scripts/ nocase ascii wide

    condition:
        any of them
}
