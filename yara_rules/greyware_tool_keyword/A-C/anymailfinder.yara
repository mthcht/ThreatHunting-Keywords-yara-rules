rule anymailfinder
{
    meta:
        description = "Detection patterns for the tool 'anymailfinder' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "anymailfinder"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: used by attackers to find informations about a company users
        // Reference: https://anymailfinder.com
        $string1 = /https\:\/\/anymailfinder\.com\/search\// nocase ascii wide

    condition:
        any of them
}
