rule sendspace_com
{
    meta:
        description = "Detection patterns for the tool 'sendspace.com' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sendspace.com"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with LockBit victims
        // Reference: https://twitter.com/mthcht/status/1660953897622544384
        $string1 = /\shttps\:\/\/www\.sendspace\.com\/file\// nocase ascii wide
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with LockBit victims
        // Reference: https://twitter.com/mthcht/status/1660953897622544384
        $string2 = /https\:\/\/.{0,1000}\.sendspace\.com\/upload/ nocase ascii wide

    condition:
        any of them
}
