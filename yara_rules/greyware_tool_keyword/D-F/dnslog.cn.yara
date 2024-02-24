rule dnslog_cn
{
    meta:
        description = "Detection patterns for the tool 'dnslog.cn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnslog.cn"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: allows users to create a unique URL to collect and inspect HTTP requests. It is commonly used for debugging webhooks - it can also be abused by attackers for verifying the reachability and effectiveness of their payloads
        // Reference: http://dnslog.cn
        $string1 = /\.dnslog\.cn\:/ nocase ascii wide
        // Description: allows users to create a unique URL to collect and inspect HTTP requests. It is commonly used for debugging webhooks - it can also be abused by attackers for verifying the reachability and effectiveness of their payloads
        // Reference: http://dnslog.cn
        $string2 = /http\:\/\/dnslog\.cn\// nocase ascii wide

    condition:
        any of them
}
