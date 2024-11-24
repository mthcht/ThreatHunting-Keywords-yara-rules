rule VNCPassView
{
    meta:
        description = "Detection patterns for the tool 'VNCPassView' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VNCPassView"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: recover the passwords stored by the VNC tool
        // Reference: https://www.nirsoft.net/utils/vnc_password.html
        $string1 = /\/utils\/vnc_password\.html/ nocase ascii wide
        // Description: recover the passwords stored by the VNC tool
        // Reference: https://www.nirsoft.net/utils/vnc_password.html
        $string2 = ">VNCPassView<" nocase ascii wide
        // Description: recover the passwords stored by the VNC tool
        // Reference: https://www.nirsoft.net/utils/vnc_password.html
        $string3 = "816d7616238958dfe0bb811a063eb3102efd82eff14408f5cab4cb5258bfd019" nocase ascii wide
        // Description: recover the passwords stored by the VNC tool
        // Reference: https://www.nirsoft.net/utils/vnc_password.html
        $string4 = "cba64638575e382bab065f43dc60b76943bce77854a80af38debeb803edb96e4" nocase ascii wide

    condition:
        any of them
}
