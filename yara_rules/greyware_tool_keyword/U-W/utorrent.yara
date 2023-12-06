rule utorrent
{
    meta:
        description = "Detection patterns for the tool 'utorrent' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "utorrent"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: popular BitTorrent client used for downloading files over the BitTorrent network. a peer-to-peer file sharing protocol. Can be used for collection and exfiltration. Not something we want to see installed in a enterprise network
        // Reference: https[://]www[.]utorrent[.]com/intl/fr/
        $string1 = /\\uTorrent\\/ nocase ascii wide
        // Description: popular BitTorrent client used for downloading files over the BitTorrent network. a peer-to-peer file sharing protocol. Can be used for collection and exfiltration. Not something we want to see installed in a enterprise network
        // Reference: https[://]www[.]utorrent[.]com/intl/fr/
        $string2 = /\\utweb\.exe/ nocase ascii wide
        // Description: popular BitTorrent client used for downloading files over the BitTorrent network. a peer-to-peer file sharing protocol. Can be used for collection and exfiltration. Not something we want to see installed in a enterprise network
        // Reference: https[://]www[.]utorrent[.]com/intl/fr/
        $string3 = /AppData\\Roaming\\uTorrent/ nocase ascii wide
        // Description: popular BitTorrent client used for downloading files over the BitTorrent network. a peer-to-peer file sharing protocol. Can be used for collection and exfiltration. Not something we want to see installed in a enterprise network
        // Reference: https[://]www[.]utorrent[.]com/intl/fr/
        $string4 = /uTorrent\s\(1\)\.exe/ nocase ascii wide
        // Description: popular BitTorrent client used for downloading files over the BitTorrent network. a peer-to-peer file sharing protocol. Can be used for collection and exfiltration. Not something we want to see installed in a enterprise network
        // Reference: https[://]www[.]utorrent[.]com/intl/fr/
        $string5 = /uTorrent\.exe/ nocase ascii wide
        // Description: popular BitTorrent client used for downloading files over the BitTorrent network. a peer-to-peer file sharing protocol. Can be used for collection and exfiltration. Not something we want to see installed in a enterprise network
        // Reference: https[://]www[.]utorrent[.]com/intl/fr/
        $string6 = /utorrent_installer\.exe/ nocase ascii wide
        // Description: popular BitTorrent client used for downloading files over the BitTorrent network. a peer-to-peer file sharing protocol. Can be used for collection and exfiltration. Not something we want to see installed in a enterprise network
        // Reference: https[://]www[.]utorrent[.]com/intl/fr/
        $string7 = /utweb_installer\.exe/ nocase ascii wide

    condition:
        any of them
}
