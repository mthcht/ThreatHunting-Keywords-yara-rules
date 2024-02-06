rule catbox_moe
{
    meta:
        description = "Detection patterns for the tool 'catbox.moe' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "catbox.moe"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: The cutest free file host you've ever seen - abused by threat actors
        // Reference: https://files[.]catbox.moe
        $string1 = /https\:\/\/files\.catbox\.moe\// nocase ascii wide

    condition:
        any of them
}
