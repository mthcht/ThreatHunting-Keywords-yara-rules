rule _1ty_me
{
    meta:
        description = "Detection patterns for the tool '1ty.me' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "1ty.me"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: temporary notes service - abused by attackers to share informations with their victims
        // Reference: https://1ty.me
        $string1 = /https\:\/\/1ty\.me\// nocase ascii wide
        // Description: temporary notes service - abused by attackers to share informations with their victims
        // Reference: https://1ty.me
        $string2 = /https\:\/\/1ty\.me\/\?mode\=ajax\&cmd\=create_note/ nocase ascii wide

    condition:
        any of them
}
