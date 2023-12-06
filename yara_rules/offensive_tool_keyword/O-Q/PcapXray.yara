rule PcapXray
{
    meta:
        description = "Detection patterns for the tool 'PcapXray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PcapXray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Given a Pcap File. plot a network diagram displaying hosts in the network. network traffic. highlight important traffic and Tor traffic as well as potential malicious traffic including data involved in the communication.
        // Reference: https://github.com/Srinivas11789/PcapXray
        $string1 = /PcapXray/ nocase ascii wide

    condition:
        any of them
}
