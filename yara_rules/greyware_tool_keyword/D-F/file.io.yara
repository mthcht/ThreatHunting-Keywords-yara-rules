rule file_io
{
    meta:
        description = "Detection patterns for the tool 'file.io' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "file.io"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with LockBit victims
        // Reference: https://twitter.com/mthcht/status/1660953897622544384
        $string1 = /https\:\/\/file\.io\// nocase ascii wide
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with LockBit victims
        // Reference: https://twitter.com/mthcht/status/1660953897622544384
        $string2 = /https\:\/\/file\.io\/\?title\=/ nocase ascii wide

    condition:
        any of them
}
