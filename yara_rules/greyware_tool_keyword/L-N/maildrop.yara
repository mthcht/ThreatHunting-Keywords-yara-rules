rule maildrop
{
    meta:
        description = "Detection patterns for the tool 'maildrop' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "maildrop"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: disposable email address to use anytime.
        // Reference: https://maildrop.cc/
        $string1 = /https\:\/\/maildrop\.cc\/inbox\/\?mailbox\=/ nocase ascii wide

    condition:
        any of them
}
