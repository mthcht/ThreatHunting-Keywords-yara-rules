rule wifiphisher
{
    meta:
        description = "Detection patterns for the tool 'wifiphisher' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wifiphisher"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The Rogue Access Point Framework.
        // Reference: https://github.com/wifiphisher/wifiphisher
        $string1 = /wifiphisher/ nocase ascii wide

    condition:
        any of them
}
