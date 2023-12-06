rule lyncsmash
{
    meta:
        description = "Detection patterns for the tool 'lyncsmash' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lyncsmash"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: default user agent used by lyncsmash.py - a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string1 = /UCCAPI\/16\.0\.13328\.20130\sOC\/16\.0\.13426\.20234/ nocase ascii wide

    condition:
        any of them
}
