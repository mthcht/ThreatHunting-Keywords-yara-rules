rule share_riseup_net
{
    meta:
        description = "Detection patterns for the tool 'share.riseup.net' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "share.riseup.net"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: temporary file hosting service - abused by attackers to share informations with their victims
        // Reference: https://share.riseup.net
        $string1 = /https\:\/\/share\.riseup\.net\/2/ nocase ascii wide
        // Description: temporary file hosting service - abused by attackers to share informations with their victims
        // Reference: https://share.riseup.net
        $string2 = /https\:\/\/share\.riseup\.net\/up/ nocase ascii wide

    condition:
        any of them
}
