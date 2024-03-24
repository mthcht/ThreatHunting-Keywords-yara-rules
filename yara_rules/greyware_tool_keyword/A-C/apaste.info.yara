rule apaste_info
{
    meta:
        description = "Detection patterns for the tool 'apaste.info' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "apaste.info"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Creating a paste on apaste.info/
        // Reference: https://apaste.info/
        $string1 = /https\:\/\/apaste\.info\/p\/new/ nocase ascii wide

    condition:
        any of them
}
