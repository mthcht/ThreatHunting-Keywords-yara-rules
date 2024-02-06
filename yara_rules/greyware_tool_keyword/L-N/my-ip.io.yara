rule my_ip_io
{
    meta:
        description = "Detection patterns for the tool 'my-ip.io' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "my-ip.io"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: abused by ransomwares
        // Reference: https://github.com/rivitna/Malware
        $string1 = /https\:\/\/api\.my\-ip\.io\/ip/ nocase ascii wide

    condition:
        any of them
}
