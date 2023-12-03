rule tcpreplay
{
    meta:
        description = "Detection patterns for the tool 'tcpreplay' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tcpreplay"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tcpreplay is a suite of free Open Source utilities for editing and replaying previously captured network traffic. Originally designed to replay malicious traffic patterns to Intrusion Detection/Prevention Systems. it has seen many evolutions including capabilities to replay to web servers.
        // Reference: https://tcpreplay.appneta.com/
        $string1 = /.{0,1000}tcpreplay.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
