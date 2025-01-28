rule put_io
{
    meta:
        description = "Detection patterns for the tool 'put.io' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "put.io"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: A storage and torrenting service abused by attackers
        // Reference: https://put.i
        $string1 = /https\:\/\/put\.io\/\?login/ nocase ascii wide
        // Description: A storage and torrenting service abused by attackers
        // Reference: https://put.i
        $string2 = /https\:\/\/put\.io\/default\/magnet\?url\=/ nocase ascii wide
        // Description: A storage and torrenting service abused by attackers
        // Reference: https://put.i
        $string3 = /https\:\/\/put\.io\/transfers/ nocase ascii wide
        // Description: A storage and torrenting service abused by attackers
        // Reference: https://put.i
        $string4 = /https\:\/\/put\.io\/v2\/oauth2\/register/ nocase ascii wide

    condition:
        any of them
}
