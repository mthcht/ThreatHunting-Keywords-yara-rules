rule gateway_finder_imp
{
    meta:
        description = "Detection patterns for the tool 'gateway-finder-imp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gateway-finder-imp"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This is an improved version of original Gateway-finder. New version rebuilt with python3 and support for files with MACs/IPs The homepage of original project is: http://pentestmonkey.net/tools/gateway-finder Gateway-finder is a scapy script that will help you determine which of the systems on the local LAN has IP forwarding enabled and which can reach the Internet.
        // Reference: https://github.com/whitel1st/gateway-finder-imp
        $string1 = /gateway\-finder/ nocase ascii wide

    condition:
        any of them
}
