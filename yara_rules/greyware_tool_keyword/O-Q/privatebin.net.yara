rule privatebin_net
{
    meta:
        description = "Detection patterns for the tool 'privatebin.net' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "privatebin.net"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with Black Basta victims
        // Reference: N/A
        $string1 = /https\:\/\/privatebin\.net\// nocase ascii wide

    condition:
        any of them
}
