rule SpamChannel
{
    meta:
        description = "Detection patterns for the tool 'SpamChannel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpamChannel"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: poof emails from any of the +2 Million domains using MailChannels
        // Reference: https://github.com/byt3bl33d3r/SpamChannel
        $string1 = /\/SpamChannel\.git/ nocase ascii wide
        // Description: poof emails from any of the +2 Million domains using MailChannels
        // Reference: https://github.com/byt3bl33d3r/SpamChannel
        $string2 = /byt3bl33d3r\/SpamChannel/ nocase ascii wide
        // Description: poof emails from any of the +2 Million domains using MailChannels
        // Reference: https://github.com/byt3bl33d3r/SpamChannel
        $string3 = /SpamChannel\-main\.zip/ nocase ascii wide

    condition:
        any of them
}
