rule hackforums_net
{
    meta:
        description = "Detection patterns for the tool 'hackforums.net' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hackforums.net"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Hack Forums - a well-known online community frequently referenced in various pieces of malicious code
        // Reference: hackforums.net
        $string1 = /hackforums\.net\// nocase ascii wide

    condition:
        any of them
}
