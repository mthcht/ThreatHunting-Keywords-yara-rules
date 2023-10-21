rule SniffAir
{
    meta:
        description = "Detection patterns for the tool 'SniffAir' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SniffAir"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SniffAir is an open-source wireless security framework which provides the ability to easily parse passively collected wireless data as well as launch sophisticated wireless attacks. SniffAir takes care of the hassle associated with managing large or multiple pcap files while thoroughly cross-examining and analyzing the traffic. looking for potential security flaws. Along with the prebuilt queries. SniffAir allows users to create custom queries for analyzing the wireless data stored in the backend SQL database. SniffAir is built on the concept of using these queries to extract data for wireless penetration test reports. The data can also be leveraged in setting up sophisticated wireless attacks included in SniffAir as modules.
        // Reference: https://github.com/Tylous/SniffAir
        $string1 = /SniffAir/ nocase ascii wide

    condition:
        any of them
}