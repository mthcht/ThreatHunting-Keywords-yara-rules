rule bittorent
{
    meta:
        description = "Detection patterns for the tool 'bittorent' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bittorent"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: popular BitTorrent client used for downloading files over the BitTorrent network. a peer-to-peer file sharing protocol. Can be used for collection and exfiltration. Not something we want to see installed in a enterprise network
        // Reference: https[://]www[.]bittorrent.com/fr/
        $string1 = /\\BitTorrent\.exe/ nocase ascii wide

    condition:
        any of them
}
