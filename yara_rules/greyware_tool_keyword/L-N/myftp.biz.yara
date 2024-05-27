rule myftp_biz
{
    meta:
        description = "Detection patterns for the tool 'myftp.biz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "myftp.biz"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: dyndns - lots of subdomains associated with malwares - could be used in various ways for both legitimate and malicious activities (malicious mostly)
        // Reference: https://github.com/hagezi/dns-blocklists/blob/9d6562bddc175b59241d5935531f648cd6b6d9c8/rpz/dyndns.txt#L103
        $string1 = /\.myftp\.biz/ nocase ascii wide

    condition:
        any of them
}
