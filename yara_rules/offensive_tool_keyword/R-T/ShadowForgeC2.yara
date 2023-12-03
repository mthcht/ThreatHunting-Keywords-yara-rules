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
        $string1 = /.{0,1000}\/ShadowForgeC2.{0,1000}/ nocase ascii wide
        // Description: ShadowForge Command & Control - Harnessing the power of Zoom API - control a compromised Windows Machine from your Zoom Chats.
        // Reference: https://github.com/0xEr3bus/ShadowForgeC2
        $string2 = /.{0,1000}cmd_powershell\.cpp.{0,1000}/ nocase ascii wide
        // Description: ShadowForge Command & Control - Harnessing the power of Zoom API - control a compromised Windows Machine from your Zoom Chats.
        // Reference: https://github.com/0xEr3bus/ShadowForgeC2
        $string3 = /.{0,1000}dist\/shadow\.exe.{0,1000}/ nocase ascii wide
        // Description: ShadowForge Command & Control - Harnessing the power of Zoom API - control a compromised Windows Machine from your Zoom Chats.
        // Reference: https://github.com/0xEr3bus/ShadowForgeC2
        $string4 = /.{0,1000}dist\\shadow\.exe.{0,1000}/ nocase ascii wide
        // Description: ShadowForge Command & Control - Harnessing the power of Zoom API - control a compromised Windows Machine from your Zoom Chats.
        // Reference: https://github.com/0xEr3bus/ShadowForgeC2
        $string5 = /.{0,1000}generate\sexe\sShadow.{0,1000}/ nocase ascii wide
        // Description: ShadowForge Command & Control - Harnessing the power of Zoom API - control a compromised Windows Machine from your Zoom Chats.
        // Reference: https://github.com/0xEr3bus/ShadowForgeC2
        $string6 = /.{0,1000}import\sShadowForgeHome.{0,1000}/ nocase ascii wide
        // Description: ShadowForge Command & Control - Harnessing the power of Zoom API - control a compromised Windows Machine from your Zoom Chats.
        // Reference: https://github.com/0xEr3bus/ShadowForgeC2
        $string7 = /.{0,1000}ShadowForge\.py.{0,1000}/ nocase ascii wide
        // Description: ShadowForge Command & Control - Harnessing the power of Zoom API - control a compromised Windows Machine from your Zoom Chats.
        // Reference: https://github.com/0xEr3bus/ShadowForgeC2
        $string8 = /.{0,1000}ShadowForgeC2\-main.{0,1000}/ nocase ascii wide
        // Description: ShadowForge Command & Control - Harnessing the power of Zoom API - control a compromised Windows Machine from your Zoom Chats.
        // Reference: https://github.com/0xEr3bus/ShadowForgeC2
        $string9 = /.{0,1000}shell\swhoami\s\/user.{0,1000}/ nocase ascii wide
        // Description: ShadowForge Command & Control - Harnessing the power of Zoom API - control a compromised Windows Machine from your Zoom Chats.
        // Reference: https://github.com/0xEr3bus/ShadowForgeC2
        $string10 = /.{0,1000}teamServer.{0,1000}ZoomAPI\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
