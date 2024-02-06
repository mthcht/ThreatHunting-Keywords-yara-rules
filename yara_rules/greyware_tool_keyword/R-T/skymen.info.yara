rule skymen_info
{
    meta:
        description = "Detection patterns for the tool 'skymen.info' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "skymen.info"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: used by attackers to find informations about a company users
        // Reference: https://www.skymem.info
        $string1 = /https\:\/\/www\.skymem\.info\/srch\?q\=/ nocase ascii wide

    condition:
        any of them
}
