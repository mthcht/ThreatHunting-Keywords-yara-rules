rule PayloadsAllTheThings
{
    meta:
        description = "Detection patterns for the tool 'PayloadsAllTheThings' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PayloadsAllTheThings"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A list of useful payloads and bypasses for Web Application Security. Feel free to improve with your payloads and techniques ! 
        // Reference: https://github.com/Bo0oM/PayloadsAllTheThings
        $string1 = /PayloadsAllTheThings/ nocase ascii wide

    condition:
        any of them
}
