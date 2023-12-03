rule tcpdump
{
    meta:
        description = "Detection patterns for the tool 'tcpdump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tcpdump"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: A powerful command-line packet analyzer.and libpcap. a portable C/C++ library for network traffic capture
        // Reference: http://www.tcpdump.org/
        $string1 = /.{0,1000}tcpdump\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
