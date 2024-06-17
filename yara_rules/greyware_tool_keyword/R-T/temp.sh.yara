rule temp_sh
{
    meta:
        description = "Detection patterns for the tool 'temp.sh' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "temp.sh"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with LockBit victims
        // Reference: https://twitter.com/mthcht/status/1660953897622544384
        $string1 = /http\:\/\/temp\.sh\/.{0,1000}\// nocase ascii wide
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with LockBit victims
        // Reference: https://twitter.com/mthcht/status/1660953897622544384
        $string2 = /https\:\/\/temp\.sh\/.{0,1000}\// nocase ascii wide
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with LockBit victims
        // Reference: https://twitter.com/mthcht/status/1660953897622544384
        $string3 = /https\:\/\/temp\.sh\/upload/ nocase ascii wide

    condition:
        any of them
}
