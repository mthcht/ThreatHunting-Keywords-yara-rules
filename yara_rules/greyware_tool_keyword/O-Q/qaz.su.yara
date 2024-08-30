rule qaz_su
{
    meta:
        description = "Detection patterns for the tool 'qaz.su' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "qaz.su"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: temporary file hosting service - abused by attackers to share informations with their victims
        // Reference: https://qaz.su/
        $string1 = /https\:\/\/qaz\.su/ nocase ascii wide
        // Description: temporary file hosting service - abused by attackers to share informations with their victims
        // Reference: https://qaz.su/
        $string2 = /https\:\/\/qaz\.su\/load\// nocase ascii wide
        // Description: temporary file hosting service - abused by attackers to share informations with their victims
        // Reference: https://qaz.su/
        $string3 = /https\:\/\/qaz\.su\/zaq\// nocase ascii wide

    condition:
        any of them
}
