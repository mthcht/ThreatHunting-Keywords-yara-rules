rule dropmefiles_com
{
    meta:
        description = "Detection patterns for the tool 'dropmefiles.com' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dropmefiles.com"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: temporary file hosting service - abused by attackers to share informations with their victims
        // Reference: https://github.com/Casualtek/Ransomchats/blob/4a25ac6ad165a4e600aeb72718c3ad41e8f6ce3a/Mallox/20230427.json#L286C25-L286C48
        $string1 = /https\:\/\/dropmefiles\.com\// nocase ascii wide
        // Description: temporary file hosting service - abused by attackers to share informations with their victims
        // Reference: https://github.com/Casualtek/Ransomchats/blob/4a25ac6ad165a4e600aeb72718c3ad41e8f6ce3a/Mallox/20230427.json#L286C25-L286C48
        $string2 = /https\:\/\/dropmefiles\.com\/s3\/upload\// nocase ascii wide

    condition:
        any of them
}
