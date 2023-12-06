rule DNSTracer
{
    meta:
        description = "Detection patterns for the tool 'DNSTracer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DNSTracer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This is a python application that traces how a DNS query is performed from a client machine to the server.
        // Reference: https://github.com/pcoder/DNSTracer
        $string1 = /dnstracer/ nocase ascii wide

    condition:
        any of them
}
