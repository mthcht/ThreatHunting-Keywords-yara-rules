rule WitnessMe
{
    meta:
        description = "Detection patterns for the tool 'WitnessMe' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WitnessMe"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: WitnessMe is primarily a Web Inventory tool inspired by Eyewitness. its also written to be extensible allowing you to create custom functionality that can take advantage of the headless browser it drives in the back-end.
        // Reference: https://github.com/byt3bl33d3r/WitnessMe
        $string1 = /WitnessMe/ nocase ascii wide

    condition:
        any of them
}
