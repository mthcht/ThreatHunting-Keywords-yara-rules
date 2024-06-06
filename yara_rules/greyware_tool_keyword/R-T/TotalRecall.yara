rule TotalRecall
{
    meta:
        description = "Detection patterns for the tool 'TotalRecall' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TotalRecall"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string1 = /\\AppData\\Local\\CoreAIPlatform\.00\\UKP\\.{0,1000}\\ukg\.db/ nocase ascii wide

    condition:
        any of them
}
