rule dirbuster
{
    meta:
        description = "Detection patterns for the tool 'dirbuster' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dirbuster"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dirbuster plugin for Burp Suite
        // Reference: https://github.com/vulnersCom/burp-Dirbuster
        $string1 = /\/burp\-Dirbuster/ nocase ascii wide

    condition:
        any of them
}
