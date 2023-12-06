rule Awesome_Hacking_Resources
{
    meta:
        description = "Detection patterns for the tool 'Awesome-Hacking-Resources' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Awesome-Hacking-Resources"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A collection of hacking / penetration testing resources to make you better!
        // Reference: https://github.com/vitalysim/Awesome-Hacking-Resources
        $string1 = /Awesome\-Hacking\-Resources/ nocase ascii wide

    condition:
        any of them
}
