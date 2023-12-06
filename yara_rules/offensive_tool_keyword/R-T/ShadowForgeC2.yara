rule ShadowForgeC2
{
    meta:
        description = "Detection patterns for the tool 'ShadowForgeC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShadowForgeC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ShadowForge Command & Control - Harnessing the power of Zoom API - control a compromised Windows Machine from your Zoom Chats.
        // Reference: https://github.com/0xEr3bus/ShadowForgeC2
        $string1 = /\/ShadowForgeC2/ nocase ascii wide
        // Description: ShadowForge Command & Control - Harnessing the power of Zoom API - control a compromised Windows Machine from your Zoom Chats.
        // Reference: https://github.com/0xEr3bus/ShadowForgeC2
        $string2 = /cmd_powershell\.cpp/ nocase ascii wide
        // Description: ShadowForge Command & Control - Harnessing the power of Zoom API - control a compromised Windows Machine from your Zoom Chats.
        // Reference: https://github.com/0xEr3bus/ShadowForgeC2
        $string3 = /dist\/shadow\.exe/ nocase ascii wide
        // Description: ShadowForge Command & Control - Harnessing the power of Zoom API - control a compromised Windows Machine from your Zoom Chats.
        // Reference: https://github.com/0xEr3bus/ShadowForgeC2
        $string4 = /dist\\shadow\.exe/ nocase ascii wide
        // Description: ShadowForge Command & Control - Harnessing the power of Zoom API - control a compromised Windows Machine from your Zoom Chats.
        // Reference: https://github.com/0xEr3bus/ShadowForgeC2
        $string5 = /generate\sexe\sShadow/ nocase ascii wide
        // Description: ShadowForge Command & Control - Harnessing the power of Zoom API - control a compromised Windows Machine from your Zoom Chats.
        // Reference: https://github.com/0xEr3bus/ShadowForgeC2
        $string6 = /import\sShadowForgeHome/ nocase ascii wide
        // Description: ShadowForge Command & Control - Harnessing the power of Zoom API - control a compromised Windows Machine from your Zoom Chats.
        // Reference: https://github.com/0xEr3bus/ShadowForgeC2
        $string7 = /ShadowForge\.py/ nocase ascii wide
        // Description: ShadowForge Command & Control - Harnessing the power of Zoom API - control a compromised Windows Machine from your Zoom Chats.
        // Reference: https://github.com/0xEr3bus/ShadowForgeC2
        $string8 = /ShadowForgeC2\-main/ nocase ascii wide
        // Description: ShadowForge Command & Control - Harnessing the power of Zoom API - control a compromised Windows Machine from your Zoom Chats.
        // Reference: https://github.com/0xEr3bus/ShadowForgeC2
        $string9 = /shell\swhoami\s\/user/ nocase ascii wide
        // Description: ShadowForge Command & Control - Harnessing the power of Zoom API - control a compromised Windows Machine from your Zoom Chats.
        // Reference: https://github.com/0xEr3bus/ShadowForgeC2
        $string10 = /teamServer.{0,1000}ZoomAPI\.py/ nocase ascii wide

    condition:
        any of them
}
