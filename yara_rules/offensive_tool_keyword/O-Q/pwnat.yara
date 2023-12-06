rule pwnat
{
    meta:
        description = "Detection patterns for the tool 'pwnat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pwnat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: pwnat. by Samy Kamkar. is a tool that allows any client behind a NAT to communicate with a server behind a separate NAT with *no* port forwarding and *no* DMZ setup on any routers in order to directly communicate with each other. Simply put. this is a proxy server that works behind a NAT. even when the client is also behind a NAT
        // Reference: https://github.com/samyk/pwnat
        $string1 = /pwnat\.exe/ nocase ascii wide

    condition:
        any of them
}
