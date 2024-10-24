rule putty
{
    meta:
        description = "Detection patterns for the tool 'putty' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "putty"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: credential cache retrieving with pscp putty
        // Reference: N/A
        $string1 = /pscp\s.{0,1000}\@.{0,1000}\.kirbi/ nocase ascii wide

    condition:
        any of them
}
