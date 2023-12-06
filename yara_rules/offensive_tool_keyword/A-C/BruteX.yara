rule BruteX
{
    meta:
        description = "Detection patterns for the tool 'BruteX' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BruteX"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Automatically brute force all services running on a target. Open ports. Usernames Passwords
        // Reference: https://github.com/1N3/BruteX
        $string1 = /BruteX/ nocase ascii wide

    condition:
        any of them
}
