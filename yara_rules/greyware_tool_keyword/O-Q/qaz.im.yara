rule qaz_im
{
    meta:
        description = "Detection patterns for the tool 'qaz.im' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "qaz.im"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: temporary file hosting service - abused by attackers to share informations with their victims
        // Reference: https://qaz.im/
        $string1 = /https\:\/\/qaz\.im\// nocase ascii wide
        // Description: temporary file hosting service - abused by attackers to share informations with their victims
        // Reference: https://qaz.im/
        $string2 = /https\:\/\/qaz\.im\/load\// nocase ascii wide
        // Description: temporary file hosting service - abused by attackers to share informations with their victims
        // Reference: https://qaz.im/
        $string3 = /https\:\/\/qaz\.im\/zaq\// nocase ascii wide

    condition:
        any of them
}
