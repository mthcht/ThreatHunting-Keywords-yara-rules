rule pydictor
{
    meta:
        description = "Detection patterns for the tool 'pydictor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pydictor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: pydictor  A powerful and useful hacker dictionary builder for a brute-force attack
        // Reference: https://github.com/LandGrey/pydictor
        $string1 = /pydictor/ nocase ascii wide

    condition:
        any of them
}
