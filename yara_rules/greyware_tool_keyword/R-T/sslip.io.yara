rule sslip_io
{
    meta:
        description = "Detection patterns for the tool 'sslip.io' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sslip.io"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: sslip.io is a DNS server that maps specially-crafted DNS A records to IP addresses e.g. 127-0-0-1.sslip.io maps to 127.0.0.1
        // Reference: https://github.com/cunnie/sslip.io
        $string1 = /http.{0,1000}\.sslip\.io/ nocase ascii wide

    condition:
        any of them
}
