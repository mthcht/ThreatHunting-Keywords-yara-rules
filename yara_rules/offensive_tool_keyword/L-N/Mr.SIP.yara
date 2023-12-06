rule Mr_SIP
{
    meta:
        description = "Detection patterns for the tool 'Mr.SIP' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Mr.SIP"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Mr.SIP is a simple console based SIP-based Audit and Attack Tool. Originally it was developed to be used in academic work to help developing novel SIP-based DDoS attacks and then as an idea to convert it to a fully functional SIP-based penetration testing tool. So far Mr SIP resulted several academic research papers. and journal articles. Mr.SIP can also be used as SIP client simulator and SIP traffic generator.
        // Reference: https://github.com/meliht/Mr.SIP
        $string1 = /meliht\/Mr\.SIP/ nocase ascii wide

    condition:
        any of them
}
