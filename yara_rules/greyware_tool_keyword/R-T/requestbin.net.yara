rule requestbin_net
{
    meta:
        description = "Detection patterns for the tool 'requestbin.net' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "requestbin.net"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: allows users to create a unique URL to collect and inspect HTTP requests. It is commonly used for debugging webhooks - it can also be abused by attackers for verifying the reachability and effectiveness of their payloads
        // Reference: http://requestbin.net
        $string1 = /\.d\.requestbin\.net/ nocase ascii wide
        // Description: allows users to create a unique URL to collect and inspect HTTP requests. It is commonly used for debugging webhooks - it can also be abused by attackers for verifying the reachability and effectiveness of their payloads
        // Reference: http://requestbin.net
        $string2 = /http\:\/\/requestbin\.net\/r\// nocase ascii wide
        // Description: allows users to create a unique URL to collect and inspect HTTP requests. It is commonly used for debugging webhooks - it can also be abused by attackers for verifying the reachability and effectiveness of their payloads
        // Reference: http://requestbin.net
        $string3 = /https\:\/\/requestbin\.net\/r\// nocase ascii wide

    condition:
        any of them
}
